package defaults

import (
	"testing"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/docker/libentitlement/secprofile"
	"github.com/stretchr/testify/require"
	"github.com/docker/libentitlement/types"
)

// FIXME factor for all defaults package and even project-wide
func testSpec() *specs.Spec {
	s := &specs.Spec{
		Process: specs.Process{
			Capabilities: &specs.LinuxCapabilities{
				Bounding:    []string{},
				Effective:   []string{},
				Inheritable: []string{},
				Permitted:   []string{},
				Ambient:     []string{},
			},
		},
		Linux: &specs.Linux{
			Seccomp:   &specs.LinuxSeccomp{},
			Resources: &specs.LinuxResources{},
			IntelRdt:  &specs.LinuxIntelRdt{},
		},
		Windows: &specs.Windows{
			Resources: &specs.WindowsResources{
				Memory:  &specs.WindowsMemoryResources{},
				CPU:     &specs.WindowsCPUResources{},
				Storage: &specs.WindowsStorageResources{},
				Network: &specs.WindowsNetworkResources{},
			},
		},
	}

	return s
}

func isEqualSeccompArgs(syscallArgs1, syscallArgs2 []specs.LinuxSeccompArg) bool {
	if len(syscallArgs1) != len(syscallArgs2) {
		return false
	}

	syscallArgMap := make(map[specs.LinuxSeccompArg]bool)

	for _, arg1 := range syscallArgs1 {
		syscallArgMap[arg1] = true
	}

	for _, arg2 := range syscallArgs2 {
		if _, ok := syscallArgMap[arg2]; !ok {
			return false
		}
	}

	return true
}

func matchSeccompRule(seccompRule specs.LinuxSyscall, syscallName string, syscallArgs []specs.LinuxSeccompArg) bool {
	for _, name := range seccompRule.Names {
		if name == syscallName {
			// FIXME: this function checks equality of arguments but we should check that provided
			// syscallArgs are a subset of whitelist rule args.
			if isEqualSeccompArgs(seccompRule.Args, syscallArgs) {
				return false
			}
		}
	}

	return true
}

func seccompSyscallWithArgBlocked(seccompProfile specs.LinuxSeccomp, syscallName string, syscallArgs []specs.LinuxSeccompArg) bool {
	blocked := seccompProfile.DefaultAction == specs.ActErrno

	if blocked {
		// For each rule in the seccomp profile, make sure that whitelisting rules don't contain this syscall
		for _, seccompRule := range seccompProfile.Syscalls {
			if seccompRule.Action == specs.ActAllow {
				// If we match a whitelisting rule containing this syscall and those arguments, syscall is not blocked
				if matchSeccompRule(seccompRule, syscallName, syscallArgs) {
					return false
				}
			}
		}
	} else {
		// For each rule in the seccomp profile, make sure that at least one blacklisting rule contain this syscall
		for _, seccompRule := range seccompProfile.Syscalls {
			if seccompRule.Action == specs.ActErrno {
				// If we match a blacklisting rule containing this syscall and those arguments, syscall is blocked
				if matchSeccompRule(seccompRule, syscallName, syscallArgs) {
					return true
				}
			}
		}
	}

	return blocked
}

func seccompSyscallsBlocked(seccompProfile specs.LinuxSeccomp, syscallNames []types.Syscall) bool {
	for _, syscallName := range syscallNames {
		syscallNameStr := string(syscallName)
		if !seccompSyscallWithArgBlocked(seccompProfile, syscallNameStr, []specs.LinuxSeccompArg{}) {
			return false
		}
	}

	return true
}

func TestNetworkNoneEntitlementEnforce(t *testing.T) {
	entitlementID := "network.none"

	ociProfile := secprofile.NewOCIProfile(testSpec(), "test-profile")

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, NetworkNoneEntFullID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	capsToRemove := []types.Capability{CapNetAdmin, CapNetBindService, CapNetRaw, CapNetBroadcast}
	for _, capToRemove := range capsToRemove {
		require.Contains(t, newOCIProfile.OCI.Process.Capabilities, capToRemove)
	}

	pathsToMask := []string{"/proc/pid/net", "/proc/sys/net", "/sys/class/net"}
	for _, pathToMask := range pathsToMask {
		require.Contains(t, newOCIProfile.OCI.Linux.MaskedPaths, pathToMask)
	}

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	for _, ns := range nsToAdd {
		require.Contains(t, newOCIProfile.OCI.Linux.Namespaces, ns)
	}

	syscallsToBlock := []types.Syscall{SysSocket, SysSocketpair, SysSetsockopt, SysGetsockopt, SysGetsockname, SysGetpeername,
									   SysBind, SysListen, SysAccept, SysAccept4, SysConnect, SysShutdown, SysRecvfrom, SysRecvmsg, SysRecvmmsg, SysSendto,
									   SysSendmsg, SysSendmmsg, SysSethostname, SysSetdomainname,
	}
	require.NotNil(t, newOCIProfile.OCI.Linux.Seccomp)
	require.True(t, seccompSyscallsBlocked(*newOCIProfile.OCI.Linux.Seccomp, syscallsToBlock))
}
