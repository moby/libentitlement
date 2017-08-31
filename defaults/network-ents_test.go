package defaults

import (
	"syscall"
	"testing"

	"github.com/docker/libentitlement/secprofile"
	"github.com/docker/libentitlement/secprofile/osdefs"
	"github.com/docker/libentitlement/testutils"
	"github.com/docker/libentitlement/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
)

func TestNetworkNoneEntitlementEnforce(t *testing.T) {
	entitlementID := NetworkNoneEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, NetworkNoneEntFullID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)

	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToRemove := []types.Capability{osdefs.CapNetAdmin, osdefs.CapNetBindService, osdefs.CapNetRaw, osdefs.CapNetBroadcast}
	require.True(t, testutils.CapsBlocked(*newOCIProfile.OCI.Process.Capabilities, capsToRemove))

	pathsToMask := []string{"/proc/pid/net", "/proc/sys/net", "/sys/class/net"}
	for _, pathToMask := range pathsToMask {
		require.Contains(t, newOCIProfile.OCI.Linux.MaskedPaths, pathToMask)
	}

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	require.True(t, testutils.NamespacesActivated(newOCIProfile.OCI.Linux.Namespaces, nsToAdd))

	require.NotNil(t, newOCIProfile.OCI.Linux.Seccomp)

	syscallsToBlock := []types.Syscall{osdefs.SysSocket, osdefs.SysSocketpair, osdefs.SysSetsockopt, osdefs.SysGetsockopt, osdefs.SysGetsockname, osdefs.SysGetpeername,
		osdefs.SysBind, osdefs.SysListen, osdefs.SysAccept, osdefs.SysAccept4, osdefs.SysConnect, osdefs.SysShutdown, osdefs.SysRecvfrom, osdefs.SysRecvmsg, osdefs.SysRecvmmsg, osdefs.SysSendto,
		osdefs.SysSendmsg, osdefs.SysSendmmsg, osdefs.SysSethostname, osdefs.SysSetdomainname,
	}
	require.True(t, testutils.SeccompSyscallsBlocked(*newOCIProfile.OCI.Linux.Seccomp, syscallsToBlock))

	syscallsWithArgsToAllow := map[types.Syscall][]specs.LinuxSeccompArg{
		osdefs.SysSocket: {
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
	require.False(t, testutils.SeccompSyscallsWithArgsBlocked(*newOCIProfile.OCI.Linux.Seccomp, syscallsWithArgsToAllow))
}

func TestNetworkUserEntitlementEnforce(t *testing.T) {
	entitlementID := NetworkUserEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, NetworkUserEntFullID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)

	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToRemove := []types.Capability{osdefs.CapNetAdmin, osdefs.CapNetBindService, osdefs.CapNetRaw}
	require.True(t, testutils.CapsBlocked(*newOCIProfile.OCI.Process.Capabilities, capsToRemove))

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	require.True(t, testutils.NamespacesActivated(newOCIProfile.OCI.Linux.Namespaces, nsToAdd))
}

func TestNetworkProxyEntitlementEnforce(t *testing.T) {
	entitlementID := NetworkProxyEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, NetworkUserEntFullID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)

	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToRemove := []types.Capability{osdefs.CapNetAdmin}
	require.True(t, testutils.CapsBlocked(*newOCIProfile.OCI.Process.Capabilities, capsToRemove))

	capsToAdd := []types.Capability{osdefs.CapNetBroadcast, osdefs.CapNetRaw, osdefs.CapNetBindService}
	require.True(t, testutils.CapsAllowed(*newOCIProfile.OCI.Process.Capabilities, capsToAdd))

	require.NotNil(t, newOCIProfile.OCI.Linux.Seccomp)

	syscallsWithArgsToBlock := map[types.Syscall][]specs.LinuxSeccompArg{
		osdefs.SysSetsockopt: {
			{
				Index:    2,
				Value:    syscall.SO_DEBUG,
				ValueTwo: 0,
				Op:       specs.OpEqualTo,
			},
		},
	}
	require.True(t, testutils.SeccompSyscallsWithArgsBlocked(*newOCIProfile.OCI.Linux.Seccomp, syscallsWithArgsToBlock))

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	require.True(t, testutils.NamespacesActivated(newOCIProfile.OCI.Linux.Namespaces, nsToAdd))
}

func TestNetworkAdminEntitlementEnforce(t *testing.T) {
	entitlementID := NetworkAdminEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, NetworkUserEntFullID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)

	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToAdd := []types.Capability{osdefs.CapNetAdmin, osdefs.CapNetRaw, osdefs.CapNetBindService, osdefs.CapNetBroadcast}
	require.True(t, testutils.CapsAllowed(*newOCIProfile.OCI.Process.Capabilities, capsToAdd))
}
