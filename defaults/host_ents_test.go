package defaults

import (
	"testing"

	"github.com/moby/libentitlement/secprofile"
	"github.com/moby/libentitlement/secprofile/osdefs"
	"github.com/moby/libentitlement/testutils"
	"github.com/moby/libentitlement/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
)

func TestHostDevicesNoneEntitlementEnforce(t *testing.T) {
	entitlementID := HostDevicesNoneEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, entitlementID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)
	require.NotNil(t, newOCIProfile.OCI.Linux.Seccomp)
	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)
	require.NotNil(t, newOCIProfile.AppArmorSetup)

	capsToRemove := []types.Capability{
		osdefs.CapSysAdmin,
	}
	require.True(t, testutils.OCICapsMatchRefWithConstraints(*newOCIProfile.OCI.Process.Capabilities, nil, capsToRemove))

	require.Contains(t, ociProfile.AppArmorSetup.Files.ReadOnly, "/sys/**")
	require.Contains(t, ociProfile.AppArmorSetup.Files.Denied, "/proc/kcore/**")
	require.Contains(t, ociProfile.OCI.Linux.ReadonlyPaths, "/sys")
	require.Contains(t, ociProfile.OCI.Linux.MaskedPaths, "/proc/kcore")

	require.Equal(t, ociProfile.OCI.Mounts, osdefs.DefaultMobyAllowedMounts)
}

func TestHostDevicesViewEntitlementEnforce(t *testing.T) {
	entitlementID := HostDevicesViewEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, entitlementID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)

	nonDefaultMounts := testutils.GetNonDefaultMounts(ociProfile.OCI.Mounts)
	require.True(t, testutils.PathListMatchRefMount(newOCIProfile.OCI.Linux.ReadonlyPaths, nonDefaultMounts))
}

func TestHostDevicesAdminEntitlementEnforce(t *testing.T) {
	entitlementID := HostDevicesAdminEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, entitlementID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)
	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)

	capsToAdd := []types.Capability{
		osdefs.CapSysAdmin,
	}
	require.True(t, testutils.OCICapsMatchRefWithConstraints(*newOCIProfile.OCI.Process.Capabilities, capsToAdd, nil))

	for _, mount := range ociProfile.OCI.Mounts {
		require.NotContains(t, mount.Options, "ro")
	}

	require.Empty(t, ociProfile.OCI.Linux.MaskedPaths)
}

func TestHostProcessesNoneEntitlementEnforce(t *testing.T) {
	entitlementID := HostProcessesNoneEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, entitlementID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)

	nsToAdd := []specs.LinuxNamespaceType{
		specs.PIDNamespace,
	}
	require.True(t, testutils.AreNamespacesActivated(newOCIProfile.OCI.Linux.Namespaces, nsToAdd))
}

func TestHostProcessesAdminEntitlementEnforce(t *testing.T) {
	entitlementID := HostProcessesAdminEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, entitlementID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	require.NotNil(t, newOCIProfile.OCI)
	require.NotNil(t, newOCIProfile.OCI.Linux)

	nsToRemove := []specs.LinuxNamespaceType{
		specs.PIDNamespace,
	}
	require.True(t, testutils.AreNamespacesDeactivated(newOCIProfile.OCI.Linux.Namespaces, nsToRemove))
}

func TestIsAllowedMount(t *testing.T) {
	defaultMount := specs.Mount{
		Destination: "/proc",
		Type:        "proc",
		Source:      "proc",
		Options:     []string{"nosuid", "noexec", "nodev"},
	}

	require.True(t, isAllowedMount(defaultMount))

	nonDefaultMount := specs.Mount{
		Destination: "/foo/bar",
		Type:        "foo",
		Source:      "bar",
		Options:     []string{},
	}

	require.False(t, isAllowedMount(nonDefaultMount))
}

func TestGetNonDefaultMount(t *testing.T) {
	nonDefaultMount := []specs.Mount{
		{
			Destination: "/foo/bar",
			Type:        "foo",
			Source:      "bar",
			Options:     []string{},
		},
	}
	require.Equal(t, nonDefaultMount, testutils.GetNonDefaultMounts(nonDefaultMount))

	defaultMount := []specs.Mount{
		{
			Destination: "/proc",
			Type:        "proc",
			Source:      "proc",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
	}
	require.Empty(t, testutils.GetNonDefaultMounts(defaultMount))
}
