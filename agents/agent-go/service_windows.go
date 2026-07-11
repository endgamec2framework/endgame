//go:build windows

package agent

import (
	"syscall"
	"time"
	"unsafe"
)

// Windows service constants
const (
	_svcWin32OwnProcess = 0x00000010
	_svcRunning         = 0x00000004
	_svcNoError         = 0x00000000
)

type _SVC_STATUS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type _SVC_TABLE_ENTRY struct {
	ServiceName *uint16
	ServiceProc uintptr
}

var (
	_advapi32             = syscall.NewLazyDLL("advapi32.dll")
	_procSetSvcStatus     = _advapi32.NewProc("SetServiceStatus")
	_procStartSvcDisp     = _advapi32.NewProc("StartServiceCtrlDispatcherW")
	_procRegSvcCtrlH      = _advapi32.NewProc("RegisterServiceCtrlHandlerW")
)

// _svcControlHandler ignores all service control requests so the agent
// keeps running even when SCM sends SERVICE_CONTROL_STOP.
var _svcControlHandler = syscall.NewCallback(func(ctrl uint32) uintptr {
	return 0
})

// _svcReady is closed when our ServiceMain has registered and reported RUNNING.
var _svcReady = make(chan struct{})

var _svcMain = syscall.NewCallback(func(argc uint32, argv **uint16) uintptr {
	// Use the service name passed by SCM (argv[0]) for registration.
	var namePtr uintptr
	if argc > 0 && argv != nil {
		namePtr = uintptr(unsafe.Pointer(*argv))
	}
	h, _, _ := _procRegSvcCtrlH.Call(namePtr, uintptr(_svcControlHandler))
	if h != 0 {
		ss := _SVC_STATUS{
			ServiceType:      _svcWin32OwnProcess,
			CurrentState:     _svcRunning,
			ControlsAccepted: 0, // accept nothing — agent controls its own lifecycle
			Win32ExitCode:    _svcNoError,
			WaitHint:         0,
		}
		_procSetSvcStatus.Call(h, uintptr(unsafe.Pointer(&ss)))
	}
	close(_svcReady)
	// Block forever — the real agent loop runs in the main goroutine.
	select {}
})

// tryRegisterAsService attempts StartServiceCtrlDispatcherW.
// If the process was launched by the Service Control Manager this registers
// our ServiceMain and sets the service status to RUNNING so SCM doesn't kill
// the process after the 30-second startup timeout.
// Returns true if running as a service, false if running interactively.
func tryRegisterAsService() bool {
	emptyName, _ := syscall.UTF16PtrFromString("")
	entry := _SVC_TABLE_ENTRY{
		ServiceName: emptyName,
		ServiceProc: _svcMain,
	}
	done := make(chan bool, 1)
	go func() {
		// StartServiceCtrlDispatcherW blocks until all services stop.
		// If NOT called from a service process it returns immediately with
		// ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063).
		ret, _, _ := _procStartSvcDisp.Call(uintptr(unsafe.Pointer(&entry)))
		done <- ret != 0
	}()

	select {
	case ok := <-done:
		// Returned quickly → not a service context (error 1063).
		return ok
	case <-time.After(250 * time.Millisecond):
		// Still blocking → we are a service. Wait for ServiceMain to report RUNNING.
		select {
		case <-_svcReady:
		case <-time.After(5 * time.Second):
		}
		return true
	}
}
