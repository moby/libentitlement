package defaults

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/moby/libentitlement/entitlement"
	"github.com/moby/libentitlement/secprofile"
	"github.com/moby/libentitlement/testutils"
)

func TestApiEntitlementEnforce(t *testing.T) {
	entitlementID := APIEntFullID

	apiEnt, ok := GetDefaultEntitlement(entitlementID)
	require.True(t, ok, fmt.Errorf("API entitlement not present"))

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")

	testAPIIDStr := "foo"
	testAPIID := secprofile.APIID(testAPIIDStr)
	testAPIValue := fmt.Sprintf("%s:%s:%s", testAPIIDStr, APIFullControl, string(secprofile.Allow))

	apiStrEnt, ok := apiEnt.(*entitlement.StringEntitlement)
	require.True(t, ok, fmt.Errorf("API entitlement is not a string entitlement"))

	err := apiStrEnt.SetValue(testAPIValue)
	require.NoError(t, err)

	refAPIRights := make(map[secprofile.APIID]map[secprofile.APISubsetID]secprofile.APIAccess)
	refAPIRights[testAPIID] = map[secprofile.APISubsetID]secprofile.APIAccess{
		secprofile.APISubsetID(APIFullControl): secprofile.Allow,
	}

	_, err = apiEnt.Enforce(ociProfile)

	// Check equality on API identifiers, API subset identifiers and API access rules
	require.True(t, reflect.DeepEqual(ociProfile.APIAccessConfig.APIRights, refAPIRights))
}

func TestGetSwarmAPIIdentifier(t *testing.T) {
	require.Equal(t, GetSwarmAPIIdentifier(), secprofile.APIID("engine.swarm"))
}

func TestIsSwarmAPIControlled(t *testing.T) {
	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")
	isControlled, access, err := IsSwarmAPIControlled(ociProfile)
	require.False(t, isControlled)
	require.Equal(t, access, secprofile.Allow)
	require.NoError(t, err)

	// FIXME: We need more error test cases
}
