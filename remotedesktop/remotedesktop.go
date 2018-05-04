package remotedesktop

import (
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

var (
	modkernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procWTSGetActiveConsoleSessionId = modkernel32.NewProc("WTSGetActiveConsoleSessionId")

	modwtsapi32           = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQueryUserToken = modwtsapi32.NewProc("WTSQueryUserToken")
)

// WTSGetActiveConsoleSessionId - see https://msdn.microsoft.com/en-us/library/aa383835(v=vs.85).aspx
func WTSGetActiveConsoleSessionId() (uint32, error) {
	r0, _, errno := syscall.Syscall(procWTSGetActiveConsoleSessionId.Addr(), 0,
		0,
		0,
		0)
	if r0 == uintptr(0xffffffff) {
		return uint32(r0), errors.Errorf("WTSGetActiveConsoleSessionId failed: %v %v", uint32(errno), errno)
	}
	return uint32(r0), nil
}

// WTSQueryUserToken - see https://msdn.microsoft.com/en-us/library/aa383840(v=vs.85).aspx
func WTSQueryUserToken(sessionID uint32) (syscall.Token, error) {
	var token syscall.Token
	r0, _, errno := syscall.Syscall(procWTSQueryUserToken.Addr(), 2,
		uintptr(sessionID),
		uintptr(unsafe.Pointer(&token)),
		0,
	)
	if r0 == 0 {
		return 0, errors.Errorf("WTSQueryUserToken failed: %v %v", uint32(errno), errno)
	}
	return token, nil
}
