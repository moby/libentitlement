package defaults

import (
	"testing"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/docker/libentitlement/secprofile"
	"github.com/stretchr/testify/require"
	"github.com/docker/libentitlement/types"
	"syscall"
)



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

	require.NotNil(t, newOCIProfile.OCI.Linux.Seccomp)

	syscallsToBlock := []types.Syscall{SysSocket, SysSocketpair, SysSetsockopt, SysGetsockopt, SysGetsockname, SysGetpeername,
									   SysBind, SysListen, SysAccept, SysAccept4, SysConnect, SysShutdown, SysRecvfrom, SysRecvmsg, SysRecvmmsg, SysSendto,
									   SysSendmsg, SysSendmmsg, SysSethostname, SysSetdomainname,
	}
	require.True(t, seccompSyscallsBlocked(*newOCIProfile.OCI.Linux.Seccomp, syscallsToBlock))

	syscallsWithArgsToAllow := map[types.Syscall][]specs.LinuxSeccompArg{
		SysSocket: {
			{
				Index: 0,
				Op:    specs.OpEqualTo,
				Value: syscall.AF_UNIX,
			},
			{
				Index: 0,
				Op:    specs.OpEqualTo,
				Value: syscall.AF_LOCAL,
			},
		},
	}
	require.True(t, seccompSyscallsWithArgsBlocked(*newOCIProfile.OCI.Linux.Seccomp, syscallsWithArgsToAllow))
}
