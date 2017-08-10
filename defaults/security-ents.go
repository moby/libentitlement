package defaults

import (
	"github.com/docker/libentitlement/defaults/osdefs"
	"github.com/docker/libentitlement/entitlement"
	"github.com/docker/libentitlement/secprofile"
	"github.com/docker/libentitlement/types"
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
	ociProfile, err := ociProfileConversionCheck(profile, SecurityConfinedEntFullID)
	if err != nil {
		return nil, err
	}

	capsToRemove := []types.Capability{
		CapMacAdmin, CapMacOverride, CapDacOverride, CapDacReadSearch, CapSetpcap, CapSetfcap, CapSetuid, CapSetgid,
		CapSysPtrace, CapFsetid, CapSysModule, CapSyslog, CapSysRawio, CapSysAdmin, CapLinuxImmutable,
	}
	ociProfile.RemoveCaps(capsToRemove...)

	syscallsToBlock := []types.Syscall{
		SysPtrace, SysArchPrctl, SysPersonality,
		// SysSetuid,
		// SysSetgid,
		// SysPrctl,
		SysMadvise,
	}
	ociProfile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToAllow := map[types.Syscall][]specs.LinuxSeccompArg{
		SysPrctl: {
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
	ociProfile, err := ociProfileConversionCheck(profile, SecurityViewEntFullID)
	if err != nil {
		return nil, err
	}

	capsToRemove := []types.Capability{
		CapSysAdmin, CapSysPtrace,
		CapSetuid, CapSetgid, CapSetpcap, CapSetfcap,
		CapMacAdmin, CapMacOverride,
		CapDacOverride, CapFsetid, CapSysModule, CapSyslog, CapSysRawio, CapLinuxImmutable,
	}
	ociProfile.RemoveCaps(capsToRemove...)

	capsToAdd := []types.Capability{CapDacReadSearch}
	ociProfile.AddCaps(capsToAdd...)

	syscallsToBlock := []types.Syscall{
		SysPtrace,
		// SysArchPrctl,
		SysPersonality, // TODO: Block NO_RANDOMIZE, COMPAT_LAYOUT args etc..
		// SysSetuid, SysSetgid,
		// SysPrctl,
		SysMadvise,
	}
	ociProfile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToAllow := map[types.Syscall][]specs.LinuxSeccompArg{
		SysPrctl: {
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
	ociProfile, err := ociProfileConversionCheck(profile, SecurityAdminEntFullID)
	if err != nil {
		return nil, err
	}

	capsToAdd := []types.Capability{
		CapMacAdmin, CapMacOverride, CapDacOverride, CapDacReadSearch, CapSetpcap, CapSetfcap, CapSetuid, CapSetgid,
		CapSysPtrace, CapFsetid, CapSysModule, CapSyslog, CapSysRawio, CapSysAdmin, CapLinuxImmutable, CapSysBoot,
		CapSysNice, CapSysPacct, CapSysTtyConfig, CapSysTime, CapWakeAlarm,
	}
	ociProfile.AddCaps(capsToAdd...)

	syscallsToAllow := []types.Syscall{
		SysPtrace, SysArchPrctl, SysPersonality, SysSetuid, SysSetgid, SysPrctl, SysMadvise, SysMount, SysInitModule,
		SysFinitModule, SysSetns, SysClone, SysUnshare,
	}
	ociProfile.AllowSyscalls(syscallsToAllow...)

	ociProfile.OCI.Linux.ReadonlyPaths = []string{}

	return ociProfile, nil
}

func securityMemoryLockEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, SecurityMemoryLockFullID)
	if err != nil {
		return nil, err
	}

	capsToAdd := []types.Capability{
		CapIpcLock,
	}
	ociProfile.AddCaps(capsToAdd...)

	syscallsToAllow := []types.Syscall{
		SysMlock, SysMunlock, SysMlock2, SysMlockall, SysMunlockall,
	}
	ociProfile.AllowSyscalls(syscallsToAllow...)

	return ociProfile, nil
}
