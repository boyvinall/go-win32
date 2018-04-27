// +build windows

// package authorization implements win32 authorization functions that don't seem to exist in other libraries
// see https://msdn.microsoft.com/en-us/library/windows/desktop/aa375742(v=vs.85).aspx
package authorization

import (
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

var (
	modadvapi32             = windows.NewLazySystemDLL("advapi32.dll")
	procGetSecurityInfo     = modadvapi32.NewProc("GetSecurityInfo")
	procSetSecurityInfo     = modadvapi32.NewProc("SetSecurityInfo")
	procSetEntriesInAclW    = modadvapi32.NewProc("SetEntriesInAclW")
	procIsValidSid          = modadvapi32.NewProc("IsValidSid")
	procSetTokenInformation = modadvapi32.NewProc("SetTokenInformation")
)

func IsValidSid(sid *syscall.SID) error {
	var err error
	r0, _, errno := syscall.Syscall(procGetSecurityInfo.Addr(), 1,
		uintptr(unsafe.Pointer(sid)),
		0,
		0)
	if r0 == 0 || errno != 0 {
		err = syscall.Errno(errno)
	}
	return err
}

// getInfo retrieves a specified type of information about an access token
// direct copy from syscall/security_windows.go
// see https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671(v=vs.85).aspx
func getInfo(t syscall.Token, class uint32, initSize int) (unsafe.Pointer, error) {
	n := uint32(initSize)
	for {
		b := make([]byte, n)
		e := syscall.GetTokenInformation(t, class, &b[0], uint32(len(b)), &n)
		if e == nil {
			return unsafe.Pointer(&b[0]), nil
		}
		if e != syscall.ERROR_INSUFFICIENT_BUFFER {
			return nil, e
		}
		if n <= uint32(len(b)) {
			return nil, e
		}
	}
}

type TokenGroups []syscall.SIDAndAttributes

// GetTokenGroups invokes GetTokenInformation, requesting TOKEN_GROUPS
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379624(v=vs.85).aspx
func GetTokenGroups(token syscall.Token) (TokenGroups, error) {
	p, err := getInfo(token, syscall.TokenGroups, 50)
	if err != nil {
		return nil, err
	}
	groupCount := *(*uint32)(p)
	if groupCount > 200 {
		// simple protection against invalid memory - how much is too much?
		return nil, errors.Errorf("invalid groupcount? %x", groupCount)
	}
	tokengroups := make(TokenGroups, groupCount)
	p = unsafe.Pointer(uintptr(p) + 8)
	for i := uint32(0); i < groupCount; i++ {
		group := *(*syscall.SIDAndAttributes)(p)
		tokengroups = append(tokengroups, group)
		p = unsafe.Pointer(uintptr(p) + unsafe.Sizeof(group))
	}
	return tokengroups, nil
}

func GetLogonSid(token syscall.Token) (*syscall.SID, error) {
	tokenGroups, err := GetTokenGroups(token)
	if err != nil {
		return nil, err
	}

	for _, g := range tokenGroups {
		if (g.Attributes & 0xC0000000) == 0xC0000000 {
			return g.Sid, nil
		}
	}

	return nil, errors.New("couldn't find logon sid")
}

// copied from internal/syscall/windows
func SetTokenInformation(tokenHandle syscall.Token, tokenInformationClass uint32, tokenInformation uintptr, tokenInformationLength uint32) error {
	var err error
	r1, _, e1 := syscall.Syscall6(procSetTokenInformation.Addr(), 4, uintptr(tokenHandle), uintptr(tokenInformationClass), uintptr(tokenInformation), uintptr(tokenInformationLength), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return err
}

func SetTokenSessionId(token syscall.Token, sessionID uint32) error {
	return SetTokenInformation(token, syscall.TokenSessionId, uintptr(unsafe.Pointer(&sessionID)), uint32(unsafe.Sizeof(sessionID)))
}

// SecurityDescriptor is win32 SECURITY_DESCRIPTOR - see https://msdn.microsoft.com/en-us/library/windows/desktop/aa379561(v=vs.85).aspx
type SecurityDescriptor struct{}

// ACL is defined at https://msdn.microsoft.com/en-us/library/windows/desktop/aa374931(v=vs.85).aspx
type ACL struct {
	AclRevision uint8
	Sbz1        uint8
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

// ObjectType is win32 SE_OBJECT_TYPE - see https://msdn.microsoft.com/en-us/library/windows/desktop/aa379593(v=vs.85).aspx
type ObjectType uint32

const (
	UnknownObjectType ObjectType = iota
	FileObject
	Service
	Printer
	RegistryKey
	LMShare
	KernelObject
	WindowObject
	DSObject
	DSObjectAll
	ProviderDefinedObject
	WmiGuidObject
	RegistryWow64_32Key
)

// SecurityInformation is win32 SECURITY_INFORMATION - https://msdn.microsoft.com/en-us/library/windows/desktop/aa379573(v=vs.85).aspx
// see also https://msdn.microsoft.com/en-us/library/windows/desktop/aa379573(v=vs.85).aspx
type SecurityInformation uint32

const (
	OwnerSecurityInformation             SecurityInformation = 0x00000001
	GroupSecurityInformation             SecurityInformation = 0x00000002
	DaclSecurityInformation              SecurityInformation = 0x00000004
	SaclSecurityInformation              SecurityInformation = 0x00000008
	LabelSecurityInformation             SecurityInformation = 0x00000010
	AttributeSecurityInformation         SecurityInformation = 0x00000020
	ScopeSecurityInformation             SecurityInformation = 0x00000040
	ProcessTrustLabelSecurityInformation SecurityInformation = 0x00000080
	BackupSecurityInformation            SecurityInformation = 0x00010000
	ProtectedDaclSecurityInformation     SecurityInformation = 0x80000000
	ProtectedSaclSecurityInformation     SecurityInformation = 0x40000000
	UnprotectedDaclSecurityInformation   SecurityInformation = 0x20000000
	UnprotectedSaclSecurityInformation   SecurityInformation = 0x10000000
)

// GetSecurityInfo - see https://msdn.microsoft.com/en-us/library/windows/desktop/aa446654(v=vs.85).aspx
func GetSecurityInfo(handle syscall.Handle,
	objectType ObjectType,
	securityInformation SecurityInformation,
	sidOwner **syscall.SID,
	sidGroup **syscall.SID,
	dacl **ACL,
	sacl **ACL,
	securityDescriptor **SecurityDescriptor) error {

	var err error
	r0, _, errno := syscall.Syscall9(procGetSecurityInfo.Addr(), 8,
		uintptr(handle),
		uintptr(objectType),
		uintptr(securityInformation),
		uintptr(unsafe.Pointer(sidOwner)),
		uintptr(unsafe.Pointer(sidGroup)),
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(sacl)),
		uintptr(unsafe.Pointer(securityDescriptor)),
		0)
	if r0 != 0 || errno != 0 {
		err = syscall.Errno(errno)
	}
	return err
}

// SetSecurityInfo - see https://msdn.microsoft.com/en-us/library/windows/desktop/aa379588(v=vs.85).aspx
func SetSecurityInfo(handle syscall.Handle,
	objectType ObjectType,
	securityInformation SecurityInformation,
	sidOwner **syscall.SID,
	sidGroup **syscall.SID,
	dacl *ACL,
	sacl *ACL) error {

	var err error
	r0, _, errno := syscall.Syscall9(procSetSecurityInfo.Addr(), 7,
		uintptr(handle),
		uintptr(objectType),
		uintptr(securityInformation),
		uintptr(unsafe.Pointer(sidOwner)),
		uintptr(unsafe.Pointer(sidGroup)),
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(sacl)),
		0,
		0)
	if r0 != 0 || errno != 0 {
		err = syscall.Errno(errno)
	}
	return err
}

type AccessMode uint32

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa374899.aspx
const (
	NotUsedAccess AccessMode = iota
	GrantAccess
	SetAccess
	DenyAccess
	RevokeAccess
	SetAuditSuccess
	SetAuditFailure
)

type InheritanceMode uint32

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa446627.aspx
// https://msdn.microsoft.com/en-us/library/aa392711(v=vs.85).aspx
const (
	NoInheritance                  InheritanceMode = 0x0
	SubObjectsOnlyInherit          InheritanceMode = 0x1
	SubContainersOnlyInherit       InheritanceMode = 0x2
	SubContainersAndObjectsInherit InheritanceMode = 0x3
	InheritNoPropagate             InheritanceMode = 0x4
	InheritOnly                    InheritanceMode = 0x8

	ObjectInheritAce      InheritanceMode = 0x1
	ContainerInheritAce   InheritanceMode = 0x2
	NoPropagateInheritAce InheritanceMode = 0x4
	InheritOnlyAce        InheritanceMode = 0x8
)

type MultipleTrusteeOperation uint32

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379284.aspx
const (
	NoMultipleTrustee MultipleTrusteeOperation = iota
	TrusteeIsImpersonate
)

type TrusteeForm uint32

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379638.aspx
const (
	TrusteeIsSid TrusteeForm = iota
	TrusteeIsName
	TrusteeBadForm
	TrusteeIsObjectsAndSid
	TrusteeIsObjectsAndName
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379636(v=vs.85).aspx
type Trustee struct {
	MultipleTrustee          *Trustee
	MultipleTrusteeOperation MultipleTrusteeOperation
	TrusteeForm              TrusteeForm
	TrusteeType              int32
	Name                     *uint16
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa446627(v=vs.85).aspx
type ExplicitAccess struct {
	AccessPermissions uint32
	AccessMode        AccessMode
	Inheritance       InheritanceMode
	Trustee           Trustee
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379576(v=vs.85).aspx
func SetEntriesInAcl(entries []ExplicitAccess, oldAcl *ACL, newAcl **ACL) error {
	var err error
	r0, _, errno := syscall.Syscall6(procSetEntriesInAclW.Addr(), 4,
		uintptr(len(entries)),
		uintptr(unsafe.Pointer(&entries[0])),
		uintptr(unsafe.Pointer(oldAcl)),
		uintptr(unsafe.Pointer(newAcl)),
		0,
		0)
	if r0 != 0 || errno != 0 {
		err = syscall.Errno(errno)
	}
	return err
}

// AddAccessRule modifies the access list for the given object
// This function and some struct/const above borrowed with thanks from https://github.com/hectane/go-acl
func AddAccessRule(handle syscall.Handle, objectType ObjectType, replace, inherit bool, entries ...ExplicitAccess) error {
	var oldAcl *ACL
	if !replace {
		var secDesc *SecurityDescriptor
		GetSecurityInfo(handle,
			objectType,
			DaclSecurityInformation,
			nil,
			nil,
			&oldAcl,
			nil,
			&secDesc)
		defer windows.LocalFree((windows.Handle)(unsafe.Pointer(secDesc)))
	}

	var acl *ACL
	err := SetEntriesInAcl(entries, oldAcl, &acl)
	if err != nil {
		return err
	}
	defer windows.LocalFree((windows.Handle)(unsafe.Pointer(acl)))

	var secInfo SecurityInformation
	if !inherit {
		secInfo = ProtectedDaclSecurityInformation
	} else {
		secInfo = UnprotectedDaclSecurityInformation
	}
	return SetSecurityInfo(handle,
		objectType,
		DaclSecurityInformation|secInfo,
		nil,
		nil,
		acl,
		nil)
}

// Create an ExplicitAccess instance granting permissions to the provided SID
func GrantSid(accessPermissions uint32, inheritance InheritanceMode, sid *syscall.SID) ExplicitAccess {
	return ExplicitAccess{
		AccessPermissions: accessPermissions,
		AccessMode:        GrantAccess,
		Inheritance:       inheritance,
		Trustee: Trustee{
			TrusteeForm: TrusteeIsSid,
			Name:        (*uint16)(unsafe.Pointer(sid)),
		},
	}
}
