// +build windows

// package windowstation implements win32 "window station" functions that don't seem to exist in other libraries
// see https://msdn.microsoft.com/en-us/library/windows/desktop/ms687107(v=vs.85).aspx
package windowstation

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Window Station Security and Access Rights - see https://msdn.microsoft.com/en-gb/library/windows/desktop/ms687391(v=vs.85).aspx
const (
	WinStaEnumDesktops    = 1
	WinStaReadAttributes  = 2
	WinStaWriteAttributes = 0x10
	WinStaEnumerate       = 0x100
	WinStaReadScreen      = 0x200
	ReadControl           = 0x00020000
	WriteDAC              = 0x00040000

	GenericReadInteractive = syscall.STANDARD_RIGHTS_READ | WinStaEnumDesktops | WinStaEnumerate | WinStaReadAttributes | WinStaReadScreen
)

var (
	moduser32                   = windows.NewLazySystemDLL("user32.dll")
	procOpenWindowStationW      = moduser32.NewProc("OpenWindowStationW")
	procCloseWindowStation      = moduser32.NewProc("CloseWindowStation")
	procGetProcessWindowStation = moduser32.NewProc("GetProcessWindowStation")
	procSetProcessWindowStation = moduser32.NewProc("SetProcessWindowStation")
)

// OpenWindowStation invokes the win32 function
// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms684339(v=vs.85).aspx
func OpenWindowStation(winSta string, inherit bool, desiredAccess uint32) (syscall.Handle, error) {
	w, err := syscall.UTF16PtrFromString(winSta)
	if err != nil {
		return 0, err
	}
	var _p0 uint32
	if inherit {
		_p0 = 1
	} else {
		_p0 = 0
	}

	r0, _, errno := syscall.Syscall(procOpenWindowStationW.Addr(), 3, uintptr(unsafe.Pointer(w)), uintptr(_p0), uintptr(desiredAccess))
	if r0 == 0 || errno != 0 {
		err = syscall.Errno(errno)
	}
	return syscall.Handle(r0), err
}

func CloseWindowStation(handle syscall.Handle) error {
	var err error
	r0, _, errno := syscall.Syscall(procCloseWindowStation.Addr(), 1, uintptr(handle), 0, 0)
	if r0 == 0 || errno != 0 {
		err = syscall.Errno(errno)
	}
	return err
}

func GetProcessWindowStation() (syscall.Handle, error) {
	var err error
	r0, _, errno := syscall.Syscall(procGetProcessWindowStation.Addr(), 0, 0, 0, 0)
	if r0 == 0 || errno != 0 {
		err = syscall.Errno(errno)
	}
	return syscall.Handle(r0), err
}

func SetProcessWindowStation(handle syscall.Handle) error {
	var err error
	r0, _, errno := syscall.Syscall(procSetProcessWindowStation.Addr(), 1, uintptr(handle), 0, 0)
	if r0 == 0 || errno != 0 {
		err = syscall.Errno(errno)
	}
	return err
}
