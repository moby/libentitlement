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
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, NetworkNoneEntFullID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)

	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToRemove := []types.Capability{CapNetAdmin, CapNetBindService, CapNetRaw, CapNetBroadcast}
	require.True(t, capsBlocked(*newOCIProfile.OCI.Process.Capabilities, capsToRemove))

	pathsToMask := []string{"/proc/pid/net", "/proc/sys/net", "/sys/class/net"}
	for _, pathToMask := range pathsToMask {
		require.Contains(t, newOCIProfile.OCI.Linux.MaskedPaths, pathToMask)
	}

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	require.True(t, namespacesActivated(newOCIProfile.OCI.Linux.Namespaces, nsToAdd))

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

func TestNetworkUserEntitlementEnforce(t *testing.T) {
	entitlementID := "network.user"

	ociProfile := secprofile.NewOCIProfile(testSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, NetworkUserEntFullID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)

	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToRemove := []types.Capability{CapNetAdmin, CapNetBindService, CapNetRaw}
	require.True(t, capsBlocked(*newOCIProfile.OCI.Process.Capabilities, capsToRemove))

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	require.True(t, namespacesActivated(newOCIProfile.OCI.Linux.Namespaces, nsToAdd))
}

func TestNetworkProxyEntitlementEnforce(t *testing.T) {
	entitlementID := "network.proxy"

	ociProfile := secprofile.NewOCIProfile(testSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, NetworkUserEntFullID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)

	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToRemove := []types.Capability{CapNetAdmin}
	require.True(t, capsBlocked(*newOCIProfile.OCI.Process.Capabilities, capsToRemove))

	capsToAdd := []types.Capability{CapNetBroadcast, CapNetRaw, CapNetBindService}
	require.True(t, capsAllowed(*newOCIProfile.OCI.Process.Capabilities, capsToAdd))

	require.NotNil(t, newOCIProfile.OCI.Linux.Seccomp)

	syscallsWithArgsToBlock := map[types.Syscall][]specs.LinuxSeccompArg{
		SysSetsockopt: {
			{
				Index:    2,
				Value:    syscall.SO_DEBUG,
				ValueTwo: 0,
				Op:       specs.OpEqualTo,
			},
		},
	}
	require.True(t, seccompSyscallsWithArgsBlocked(*newOCIProfile.OCI.Linux.Seccomp, syscallsWithArgsToBlock))

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	require.True(t, namespacesActivated(newOCIProfile.OCI.Linux.Namespaces, nsToAdd))
}

func TestNetworkAdminEntitlementEnforce(t *testing.T) {
	entitlementID := "network.admin"

	ociProfile := secprofile.NewOCIProfile(testSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, NetworkUserEntFullID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)

	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToAdd := []types.Capability{CapNetAdmin, CapNetRaw, CapNetBindService, CapNetBroadcast}
	require.True(t, capsAllowed(*newOCIProfile.OCI.Process.Capabilities, capsToAdd))
}