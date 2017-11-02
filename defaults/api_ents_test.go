package defaults

import (
	"fmt"
	"testing"
	"github.com/stretchr/testify/require"
	"reflect"

	"github.com/moby/libentitlement/entitlement"
	"github.com/moby/libentitlement/secprofile"
	"github.com/moby/libentitlement/testutils"
)

func TestApiEntitlementEnforce(t *testing.T) {
	entitlementID := APIEntFullID
	require.NotNil(t, DefaultEntitlements[entitlementID])

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")

	apiEnt, ok := GetDefaultEntitlement(entitlementID)
	require.True(t, ok, fmt.Errorf("API entitlement not present"))

	testAPIIDStr := "foo"
	testAPIID := secprofile.APIID(testAPIIDStr)
	testAPIValue := fmt.Sprintf("%s:%s:%s", testAPIIDStr, APIFullControl, string(secprofile.Allow))

	apiStrEnt := entitlement.StringEntitlement(apiEnt)
	err := apiStrEnt.SetValue(testAPIValue)
	require.NoError(t, err)

	refAPIAccessConfig := secprofile.APIAccessConfig{APIRights: make(map[secprofile.APIID]map[secprofile.APISubsetID]secprofile.APIAccess)}
	refAPIAccessConfig.APIRights[testAPIID] = map[secprofile.APISubsetID]secprofile.APIAccess{
		secprofile.APISubsetID(APIFullControl): secprofile.Allow,
	}

	_, err = apiEnt.Enforce(ociProfile)
	// Check equality on API identifier
	require.Equal(t, reflect.ValueOf(ociProfile.APIAccessConfig.APIRights).MapKeys(), reflect.ValueOf(refAPIAccessConfig.APIRights).MapKeys())
	// Check equality on API subsets identifier
	require.Equal(t, reflect.ValueOf(ociProfile.APIAccessConfig.APIRights[testAPIID]).MapKeys(), reflect.ValueOf(refAPIAccessConfig.APIRights[testAPIID]).MapKeys())
	// Check equality on the access rule
	require.Equal(t, ociProfile.APIAccessConfig.APIRights[testAPIID][secprofile.APISubsetID(APIFullControl)], refAPIAccessConfig.APIRights[testAPIID][secprofile.APISubsetID(APIFullControl)])

	//	require.NoError(t, err, "Failed to enforce while testing entitlement %s", entitlementID)

	//	newOCIProfile, err := ociProfileConversionCheck(newProfile, APIEntAllowID)
	//	require.NoError(t, err, "Failed converting to OCI profile while testing entitlement %s", entitlementID)
	//
	//	require.NotNil(t, newOCIProfile.OCI)
	//	require.NotNil(t, newOCIProfile.OCI.Linux)
	//
	//	require.NotNil(t, newOCIProfile.OCI.Process.Capabilities)
}
