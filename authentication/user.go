// +build windows

// package authentication implements win32 authentication functions that don't seem to exist in other libraries
// see https://msdn.microsoft.com/en-us/library/windows/desktop/aa374731(v=vs.85).aspx
package authentication

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32    = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW = modadvapi32.NewProc("LogonUserW")
)

const (
	LogonInteractive = 2

	LogonProviderDefault = 0
)

func LogonUser(username, domain, password string, loginType, loginProvider uint32) (syscall.Token, error) {
	u, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return 0, err
	}

	d, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		return 0, err
	}

	p, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return 0, err
	}

	var token syscall.Token
	r0, _, errno := syscall.Syscall6(procLogonUserW.Addr(), 6, uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(p)), uintptr(loginType), uintptr(loginProvider), uintptr(unsafe.Pointer(&token)))
	if r0 != 1 || errno != 0 {
		err = syscall.Errno(errno)
	}

	return token, err
}
