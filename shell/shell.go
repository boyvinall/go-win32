package shell

// https://docs.microsoft.com/en-us/windows/desktop/api/userenv/

import (
	"os"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	userenv = windows.NewLazySystemDLL("userenv.dll")

	procCreateEnvironmentBlock  = userenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock = userenv.NewProc("DestroyEnvironmentBlock")
)

// CreateEnvironmentBlock - see https://msdn.microsoft.com/en-us/library/windows/desktop/bb762270(v=vs.85).aspx
func CreateEnvironmentBlock(
	lpEnvironment *uintptr, // LPVOID*
	hToken syscall.Token, // HANDLE
	bInherit bool, // BOOL
) (err error) {
	inherit := uint32(0)
	if bInherit {
		inherit = 1
	}
	r1, _, e1 := procCreateEnvironmentBlock.Call(
		uintptr(unsafe.Pointer(lpEnvironment)),
		uintptr(hToken),
		uintptr(inherit),
	)
	if r1 == 0 {
		err = os.NewSyscallError("CreateEnvironmentBlock", e1)
	}
	return
}

// DestroyEnvironmentBlock - see https://msdn.microsoft.com/en-us/library/windows/desktop/bb762274(v=vs.85).aspx
func DestroyEnvironmentBlock(
	lpEnvironment uintptr, // LPVOID - beware - unlike LPVOID* in CreateEnvironmentBlock!
) (err error) {
	r1, _, e1 := procDestroyEnvironmentBlock.Call(
		lpEnvironment,
	)
	if r1 == 0 {
		err = os.NewSyscallError("DestroyEnvironmentBlock", e1)
	}
	return
}

// CreateEnvironment returns a slice of environment variables for the user in the specified token
func CreateEnvironment(hUser syscall.Token) ([]string, error) {
	var userEnv uintptr
	err := CreateEnvironmentBlock(&userEnv, hUser, false)
	if err != nil {
		return nil, err
	}
	defer DestroyEnvironmentBlock(userEnv)
	offset := uint(0)
	env := []string{}
	for {
		v := syscall.UTF16ToString((*[1 << 15]uint16)(unsafe.Pointer(userEnv + uintptr(offset)))[:])
		if v == "" {
			break
		}
		env = append(env, v)
		// in UTF16, each rune takes two bytes, as does the trailing uint16(0)
		offset += uint(2 * (utf8.RuneCountInString(v) + 1))
	}
	return env, nil
}
