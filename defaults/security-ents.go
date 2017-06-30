package defaults

import (
	"fmt"

	"github.com/docker/libentitlement/defaults/osdefs"
	"github.com/docker/libentitlement/entitlement"
	"github.com/docker/libentitlement/secprofile"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	securityDomain = "security"
)

const (
	// SecurityConfinedEntFullID is the ID for the security.confined entitlement
	SecurityConfinedEntFullID = securityDomain + ".confined"
	// SecurityViewEntFullID is the ID for the security.view entitlement
	SecurityViewEntFullID = securityDomain + ".view"
	// SecurityAdminEntFullID is the ID for the security.admin entitlement
	SecurityAdminEntFullID = securityDomain + ".admin"
	// SecurityMemoryLockFullID is the ID for the security.memory-lock entitlement
	SecurityMemoryLockFullID = securityDomain + ".memory-lock"
)

var (
	securityConfinedEntitlement   = entitlement.NewVoidEntitlement(SecurityConfinedEntFullID, securityConfinedEntitlementEnforce)
	securityViewEntitlement       = entitlement.NewVoidEntitlement(SecurityViewEntFullID, securityViewEntitlementEnforce)
	securityAdminEntitlement      = entitlement.NewVoidEntitlement(SecurityAdminEntFullID, securityAdminEntitlementEnforce)
	securityMemoryLockEntitlement = entitlement.NewVoidEntitlement(SecurityMemoryLockFullID, securityMemoryLockEnforce)
)

func securityConfinedEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	if profile.GetType() != secprofile.OCIProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", SecurityConfinedEntFullID)
	}

	ociProfile, ok := profile.(*secprofile.OCIProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", SecurityConfinedEntFullID)
	}

	capsToRemove := []string{"CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
		"CAP_SETPCAP", "CAP_SETFCAP", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_PTRACE", "CAP_FSETID", "CAP_SYS_MODULE",
		"CAP_SYSLOG", "CAP_SYS_RAWIO", "CAP_SYS_ADMIN", "CAP_LINUX_IMMUTABLE",
	}
	ociProfile.RemoveCaps(capsToRemove...)

	syscallsToBlock := []string{"ptrace", "arch_prctl", "personality", "setuid", "setgid", "prctl",
		"madvise",
	}
	ociProfile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToAllow := map[string][]specs.LinuxSeccompArg{
		"prctl": {
			{
				Index: 0,
				Value: osdefs.PrCapbsetDrop,
				Op:    specs.OpNotEqual,
			},
			{
				Index: 0,
				Value: osdefs.PrCapbsetRead,
				Op:    specs.OpNotEqual,
			},
		},
	}
	ociProfile.AllowSyscallsWithArgs(syscallsWithArgsToAllow)

	/* FIXME: Add AppArmor rules to deny RW on sensitive FS directories */

	return ociProfile, nil
}

func securityViewEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	if profile.GetType() != secprofile.OCIProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", SecurityViewEntFullID)
	}

	ociProfile, ok := profile.(*secprofile.OCIProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", SecurityViewEntFullID)
	}

	capsToRemove := []string{"CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP",
		"CAP_SETFCAP", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_DAC_OVERRIDE", "CAP_FSETID",
		"CAP_SYS_MODULE", "CAP_SYSLOG", "CAP_SYS_RAWIO", "CAP_LINUX_IMMUTABLE",
	}
	ociProfile.RemoveCaps(capsToRemove...)

	capsToAdd := []string{"CAP_DAC_READ_SEARCH"}
	ociProfile.AddCaps(capsToAdd...)

	syscallsToBlock := []string{"ptrace", "arch_prctl", "personality", "setuid", "setgid", "prctl",
		"madvise",
	}
	ociProfile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToAllow := map[string][]specs.LinuxSeccompArg{
		"prctl": {
			{
				Index: 0,
				Value: osdefs.PrCapbsetDrop,
				Op:    specs.OpNotEqual,
			},
		},
	}
	ociProfile.AllowSyscallsWithArgs(syscallsWithArgsToAllow)

	/* FIXME: Add AppArmor rules to RO on sensitive FS directories */

	return ociProfile, nil
}

func securityAdminEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	if profile.GetType() != secprofile.OCIProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", SecurityAdminEntFullID)
	}

	ociProfile, ok := profile.(*secprofile.OCIProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", SecurityAdminEntFullID)
	}

	capsToAdd := []string{
		"CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
		"CAP_SETPCAP", "CAP_SETFCAP", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_PTRACE", "CAP_FSETID", "CAP_SYS_MODULE",
		"CAP_SYSLOG", "CAP_SYS_RAWIO", "CAP_SYS_ADMIN", "CAP_LINUX_IMMUTABLE",
	}
	ociProfile.AddCaps(capsToAdd...)

	syscallsToAllow := []string{"ptrace", "arch_prctl", "personality", "setuid", "setgid", "prctl",
		"madvise",
	}
	ociProfile.AllowSyscalls(syscallsToAllow...)

	return ociProfile, nil
}

func securityMemoryLockEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	if profile.GetType() != secprofile.OCIProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", SecurityMemoryLockFullID)
	}

	ociProfile, ok := profile.(*secprofile.OCIProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", SecurityMemoryLockFullID)
	}

	capsToAdd := []string{
		"CAP_IPC_LOCK",
	}
	ociProfile.AddCaps(capsToAdd...)

	syscallsToAllow := []string{
		"mlock", "munlock", "mlock2", "mlockall", "munlockall",
	}
	ociProfile.AllowSyscalls(syscallsToAllow...)

	return ociProfile, nil
}
