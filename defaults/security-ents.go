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

/* Implements "security.confined" entitlement:
 * - Blocked caps: CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SETUID, CAP_SETGID, CAP_SETPCAP, CAP_SETFCAP, CAP_MAC_ADMIN,
 *					CAP_MAC_OVERRIDE, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FSETID, CAP_SYS_MODULE, CAP_SYSLOG,
 * 					CAP_SYS_RAWIO, CAP_LINUX_IMMUTABLE
 * - Blocked syscalls: ptrace, arch_prctl, personality, madvise, prctl with PR_CAPBSET_DROP and PR_CAPBSET_READ
 */
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
		SysPtrace, SysArchPrctl, SysPersonality, SysMadvise,
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

/* Implements "security.view" entitlement:
 * - Blocked caps: CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SETUID, CAP_SETGID, CAP_SETPCAP, CAP_SETFCAP, CAP_MAC_ADMIN,
 *					CAP_MAC_OVERRIDE, CAP_DAC_OVERRIDE, CAP_FSETID, CAP_SYS_MODULE, CAP_SYSLOG, CAP_SYS_RAWIO,
 *					CAP_LINUX_IMMUTABLE
 * - Authorized caps: CAP_DAC_READ_SEARCH
 * - Blocked Syscalls: ptrace, personality, madvise, prctl with PR_CAPBSET_DROP
 */
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
		SysPersonality,
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

/* Implements "security.admin" entitlement:
 * - Authorized caps: CAP_MAC_ADMIN, CAP_MAC_OVERRIDE, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_SETPCAP, CAP_SETFCAP,
 * 						CAP_SETUID, CAP_SETGID, CAP_SYS_PTRACE, CAP_FSETID, CAP_SYS_MODULE, CAP_SYSLOG, CAP_SYS_RAWIO,
 *						CAP_SYS_ADMIN, CAP_LINUX_IMMUTABLE, CAP_SYS_BOOT, CAP_SYS_NICE, CAP_SYS_PACCT,
 *						CAP_SYS_TTY_CONFIG, CAP_SYS_TIME, CAP_WAKE_ALARM
 * - Allowed syscalls: ptrace, arch_prctl, personality, setuid, setgid, prctl, madvise, mount, init_module,
 *						finit_module, setns, clone, unshare
 * - No read-only paths
 */
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

	// Just in case some default configuration does add read-only paths, we remove them
	ociProfile.OCI.Linux.ReadonlyPaths = []string{}

	return ociProfile, nil
}

/* Implements "security.memory-lock" entitlement:
 * - Authorized caps: CAP_IPC_LOCK
 * - Allowed syscalls: mlock, munlock, mlockall, munlockall
 */
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
