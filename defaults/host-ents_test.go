package defaults

import (
	"github.com/docker/libentitlement/secprofile"
	"github.com/docker/libentitlement/secprofile/osdefs"
	"github.com/docker/libentitlement/testutils"
	"github.com/docker/libentitlement/types"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDevicesNoneEntitlementEnforce(t *testing.T) {
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

func TestDevicesViewEntitlementEnforce(t *testing.T) {
	entitlementID := HostDevicesViewEntFullID

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	require.Contains(t, DefaultEntitlements, entitlementID)

	ent := DefaultEntitlements[entitlementID]

	newProfile, err := ent.Enforce(ociProfile)
	require.NoError(t, err, "Failed enforce while testing entitlement %s", entitlementID)

	newOCIProfile, err := ociProfileConversionCheck(newProfile, entitlementID)
	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)

	nonDefaultMounts := testutils.GetNonDefaultMounts(ociProfile.OCI.Mounts)
	require.True(t, testutils.PathListMatchRefMount(newOCIProfile.OCI.Linux.ReadonlyPaths, nonDefaultMounts))
}
