package defaults

import (
	"fmt"
	"testing"

	"github.com/docker/libentitlement/secprofile"
	"github.com/docker/libentitlement/testutils"
	"github.com/stretchr/testify/require"
)

func TestApiEntitlementEnforce(t *testing.T) {
	entitlementID := APIEntAllowID
	require.NotNil(t, DefaultEntitlements[entitlementID])

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	apiEnt := DefaultEntitlements[entitlementID]

	_, err := apiEnt.Enforce(ociProfile)
	require.Equal(t, fmt.Errorf("OCI profile's APIAccess field nil"), err)

	//	require.NoError(t, err, "Failed to enforce while testing entitlement %s", entitlementID)

	//	newOCIProfile, err := ociProfileConversionCheck(newProfile, APIEntAllowID)
	//	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)
	//
	//	require.NotNil(t, newOCIProfile.OCI)
	//	require.NotNil(t, newOCIProfile.OCI.Linux)
	//
	//	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)
}
