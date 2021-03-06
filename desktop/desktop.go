// +build windows

// package windowstation implements win32 "desktop" functions that don't seem to exist in other libraries
// see https://msdn.microsoft.com/en-us/library/windows/desktop/ms687107(v=vs.85).aspx
package desktop

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	moduser32        = windows.NewLazySystemDLL("user32.dll")
	procOpenDesktopW = moduser32.NewProc("OpenDesktopW")
	procCloseDesktop = moduser32.NewProc("CloseDesktop")
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682575(v=vs.85).aspx
const (
	CreateMenu      = 0x0004
	CreateWindow    = 0x0002
	Enumerate       = 0x0040
	HookControl     = 0x0008
	JournalPlayback = 0x0020
	JournalRecord   = 0x0010
	ReadObjects     = 0x0001
	SwitchDesktop   = 0x0100
	WriteObjects    = 0x0080

	Delete           = 0x00010000
	ReadPermissions  = 0x00020000
	WritePermissions = 0x00040000
	TakeOwnership    = 0x00080000
	Synchronize      = 0x00100000

	GenericRead = Enumerate | ReadObjects | syscall.STANDARD_RIGHTS_READ
	Write       = syscall.STANDARD_RIGHTS_WRITE | WriteObjects | CreateWindow | CreateMenu | HookControl | JournalRecord | JournalPlayback
	Execute     = syscall.STANDARD_RIGHTS_EXECUTE | SwitchDesktop

	AllAccess = syscall.STANDARD_RIGHTS_REQUIRED | ReadObjects | CreateWindow | CreateMenu | HookControl | JournalRecord | JournalPlayback | Enumerate | WriteObjects | SwitchDesktop
)

// OpenDesktop invokes the win32 function
// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms684303(v=vs.85).aspx
func OpenDesktop(desktop string, flags uint32, inherit bool, desiredAccess uint32) (syscall.Handle, error) {
	d, err := syscall.UTF16PtrFromString(desktop)
	if err != nil {
		return 0, err
	}
	var _p0 uint32
	if inherit {
		_p0 = 1
	} else {
		_p0 = 0
	}

	r0, _, errno := syscall.Syscall6(procOpenDesktopW.Addr(), 4, uintptr(unsafe.Pointer(d)), uintptr(flags), uintptr(_p0), uintptr(desiredAccess), 0, 0)
	if r0 == 0 || errno != 0 {
		err = syscall.Errno(errno)
	}
	return syscall.Handle(r0), err
}

// CloseDesktop - https://msdn.microsoft.com/en-us/library/windows/desktop/ms682024(v=vs.85).aspx
func CloseDesktop(handle syscall.Handle) error {
	var err error
	r0, _, errno := syscall.Syscall(procCloseDesktop.Addr(), 1, uintptr(handle), 0, 0)
	if r0 == 0 || errno != 0 {
		err = syscall.Errno(errno)
	}
	return err
}
