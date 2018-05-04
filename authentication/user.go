// +build windows

// package authentication implements win32 authentication functions that don't seem to exist in other libraries
// see https://msdn.microsoft.com/en-us/library/windows/desktop/aa374731(v=vs.85).aspx
package authentication

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32    = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW = modadvapi32.NewProc("LogonUserW")

	modsecur32                    = windows.NewLazySystemDLL("secur32.dll")
	procLsaEnumerateLogonSessions = modsecur32.NewProc("LsaEnumerateLogonSessions")
	procLsaFreeReturnBuffer       = modsecur32.NewProc("LsaFreeReturnBuffer")
	procLsaGetLogonSessionData    = modsecur32.NewProc("LsaGetLogonSessionData")
)

// https://msdn.microsoft.com/en-gb/library/windows/desktop/aa378184(v=vs.85).aspx
const (
	LogonInteractive = 2

	LogonProviderDefault = 0
)

// LogonUser - https://msdn.microsoft.com/en-gb/library/windows/desktop/aa378184(v=vs.85).aspx
func LogonUser(username, domain, password string, logonType, logonProvider uint32) (syscall.Token, error) {
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
	r0, _, errno := syscall.Syscall6(procLogonUserW.Addr(), 6, uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(p)), uintptr(logonType), uintptr(logonProvider), uintptr(unsafe.Pointer(&token)))
	if r0 != 1 || errno != 0 {
		err = syscall.Errno(errno)
	}

	return token, err
}

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type PLUID *LUID

type LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type SecurityLogonType uint32

const (
	SLTInteractive SecurityLogonType = iota + 2
	SLTNetwork
	SLTBatch
	SLTService
	SLTProxy
	SLTUnlock
	SLTNetworkCleartext
	SLTNewCredentials
	SLTRemoteInteractive
	SLTCachedInteractive
	SLTCachedRemoteInteractive
	SLTCachedUnlock
)

type securityLogonSessionData struct {
	Size                  uint32
	LogonId               LUID
	UserName              LSA_UNICODE_STRING
	LogonDomain           LSA_UNICODE_STRING
	AuthenticationPackage LSA_UNICODE_STRING
	LogonType             SecurityLogonType
	Session               uint32
	Sid                   uintptr
	LogonTime             uint64
	LogonServer           LSA_UNICODE_STRING
	DnsDomainName         LSA_UNICODE_STRING
	Upn                   LSA_UNICODE_STRING
}

type SecurityLogonSessionData struct {
	Size                  uint32
	LogonId               LUID
	UserName              string
	LogonDomain           string
	AuthenticationPackage string
	LogonType             SecurityLogonType
	Session               uint32
	Sid                   uintptr
	LogonTime             uint64
	LogonServer           string
	DnsDomainName         string
	Upn                   string
}

// GetLogonSessions combines the following win32 functions:
// LsaEnumerateLogonSessions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa378275(v=vs.85).aspx
// LsaGetLogonSessionData - https://msdn.microsoft.com/en-us/library/windows/desktop/aa378290(v=vs.85).aspx
func GetLogonSessions() ([]SecurityLogonSessionData, error) {
	var logonSessions []SecurityLogonSessionData

	var count uint64
	var pluid PLUID
	r0, _, errno := syscall.Syscall(procLsaEnumerateLogonSessions.Addr(), 2,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&pluid)),
		0,
	)
	if r0 != 0 || errno != 0 {
		return nil, syscall.Errno(errno)
	}
	defer syscall.Syscall(procLsaFreeReturnBuffer.Addr(), 1, uintptr(unsafe.Pointer(&pluid)), 0, 0)

	for i := uint64(0); i < count; i++ {
		var pSessionData *securityLogonSessionData

		r0, _, errno := syscall.Syscall(procLsaGetLogonSessionData.Addr(), 2, uintptr(unsafe.Pointer(pluid)), uintptr(unsafe.Pointer(&pSessionData)), 0)
		if r0 != 0 || errno != 0 {
			return nil, syscall.Errno(errno)
		}

		if pSessionData == nil {
			return nil, errors.New("session data is nil")
		}

		logonSessions = append(logonSessions, SecurityLogonSessionData{
			Size:                  pSessionData.Size,
			LogonId:               pSessionData.LogonId,
			UserName:              pSessionData.UserName.String(),
			LogonDomain:           "",
			AuthenticationPackage: "",
			LogonType:             pSessionData.LogonType,
			Session:               pSessionData.Session,
			Sid:                   pSessionData.Sid,
			LogonTime:             pSessionData.LogonTime,
			LogonServer:           pSessionData.LogonServer.String(),
			DnsDomainName:         pSessionData.DnsDomainName.String(),
			Upn:                   pSessionData.Upn.String(),
		})

		syscall.Syscall(procLsaFreeReturnBuffer.Addr(), 1, uintptr(unsafe.Pointer(pSessionData)), 0, 0)

		pluid = PLUID(unsafe.Pointer(uintptr(unsafe.Pointer(pluid)) + unsafe.Sizeof(*pluid)))
	}

	return logonSessions, nil
}

func (us *LSA_UNICODE_STRING) String() string {
	return syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(us.Buffer))[:us.Length])
}

func GetUserLogonSessions(username string) ([]SecurityLogonSessionData, error) {
	var userSessions []SecurityLogonSessionData
	allSessions, err := GetLogonSessions()
	if err != nil {
		return nil, err
	}
	for _, s := range allSessions {
		if strings.ToLower(s.UserName) == strings.ToLower(username) {
			userSessions = append(userSessions, s)
		}
	}
	return userSessions, nil
}
