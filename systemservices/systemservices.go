package systemservices

import (
	"os"

	"golang.org/x/sys/windows"
)

const (
	ES_SYSTEM_REQUIRED   = 0x00000001
	ES_DISPLAY_REQUIRED  = 0x00000002
	ES_USER_PRESENT      = 0x00000004
	ES_AWAYMODE_REQUIRED = 0x00000040
	ES_CONTINUOUS        = 0x80000000
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procSetThreadExecutionState = kernel32.NewProc("SetThreadExecutionState")
)

// SetThreadExecutionState - see https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadexecutionstate
func SetThreadExecutionState(esFlags uint32) (esFlagsOut uint32, err error) {
	r1, _, e1 := procSetThreadExecutionState.Call(
		uintptr(esFlags),
	)
	if r1 == 0 {
		err = os.NewSyscallError("SetThreadExecutionState", e1)
	}
	esFlagsOut = uint32(r1)
	return
}
