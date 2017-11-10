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

func TestAPIEntitlementEnforceAllow(t *testing.T) {
	entitlementID := APIEntFullID

	apiEnt, ok := GetDefaultEntitlement(entitlementID)
	require.True(t, ok, fmt.Errorf("API entitlement not present"))

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")

	testAPIIDStr := "foo"
	testAPIID := secprofile.APIID(testAPIIDStr)
	// Generate "foo:all:allow"
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
	require.NoError(t, err)

	// Check equality on API identifiers, API subset identifiers and API access rules
	require.True(t, reflect.DeepEqual(ociProfile.APIAccessConfig.APIRights, refAPIRights))
}

type invalidProfile struct{}

func (p *invalidProfile) GetType() secprofile.ProfileType {
	return secprofile.ProfileType("invalid-profile")
}

type nilAPIAccessConfigProfile struct{}

func (p *nilAPIAccessConfigProfile) GetType() secprofile.ProfileType {
	return secprofile.OCIProfileType
}

func TestAPIEntitlementEnforceErrors(t *testing.T) {
	entitlementID := APIEntFullID

	apiEnt, ok := GetDefaultEntitlement(entitlementID)
	require.True(t, ok, fmt.Errorf("API entitlement not present"))

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")

	testAPIIDStr := "foo"
	// Generate "foo:all"
	testAPIValue := fmt.Sprintf("%s:%s", testAPIIDStr, APIFullControl)

	apiStrEnt, ok := apiEnt.(*entitlement.StringEntitlement)
	require.True(t, ok, fmt.Errorf("API entitlement is not a string entitlement"))

	err := apiStrEnt.SetValue(testAPIValue)
	require.NoError(t, err)

	_, err = apiEnt.Enforce(ociProfile)
	require.Equal(t, err, fmt.Errorf("Wrong API subset and access format, should be \"api-id:subset:[allow|deny]\""))
	// Generate "foo:all:baz"
	testAPIValue = fmt.Sprintf("%s:%s:baz", testAPIIDStr, APIFullControl)

	err = apiStrEnt.SetValue(testAPIValue)
	require.NoError(t, err)

	_, err = apiEnt.Enforce(ociProfile)
	require.Equal(t, err, fmt.Errorf("Wrong API subset and access format, should be \"api-id:subset:[allow|deny]\""))

	_, err = apiEnt.Enforce(&invalidProfile{})
	require.Equal(t, err, fmt.Errorf("api.access not implemented for non-OCI profiles"))

	_, err = apiEnt.Enforce(&nilAPIAccessConfigProfile{})
	require.Equal(t, err, fmt.Errorf("api.access: error converting to OCI profile"))
}

func TestGetSwarmAPIIdentifier(t *testing.T) {
	require.Equal(t, GetSwarmAPIIdentifier(), secprofile.APIID("engine.swarm"))
}

func TestIsSwarmAPIControlled(t *testing.T) {
	type test struct {
		profile          secprofile.Profile
		wantIsControlled bool
		wantAccess       secprofile.APIAccess
		wantErr          error
	}

	tests := []test{
		{
			profile:          nil,
			wantIsControlled: false,
			wantAccess:       secprofile.Allow,
			wantErr:          fmt.Errorf("profile is nil for %s", APIEntFullID),
		},
		{
			profile: &secprofile.OCIProfile{
				OCI:             nil,
				AppArmorSetup:   nil,
				APIAccessConfig: nil,
			},
			wantIsControlled: false,
			wantAccess:       secprofile.Allow,
			wantErr:          fmt.Errorf("OCI profile's APIAccess field nil"),
		},
		{
			profile:          secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile"),
			wantIsControlled: false,
			wantAccess:       secprofile.Allow,
			wantErr:          nil,
		},
		{
			profile: &secprofile.OCIProfile{
				OCI:           nil,
				AppArmorSetup: nil,
				APIAccessConfig: &secprofile.APIAccessConfig{
					APIRights: map[secprofile.APIID]map[secprofile.APISubsetID]secprofile.APIAccess{
						GetSwarmAPIIdentifier(): {},
					},
				},
			},
			wantIsControlled: false,
			wantAccess:       secprofile.Allow,
			wantErr:          nil,
		},
		{
			profile: &secprofile.OCIProfile{
				OCI:           nil,
				AppArmorSetup: nil,
				APIAccessConfig: &secprofile.APIAccessConfig{
					APIRights: map[secprofile.APIID]map[secprofile.APISubsetID]secprofile.APIAccess{
						GetSwarmAPIIdentifier(): {
							APIFullControl: secprofile.Deny,
						},
					},
				},
			},
			wantIsControlled: true,
			wantAccess:       secprofile.Deny,
			wantErr:          nil,
		},
	}

	for _, test := range tests {
		isControlled, access, err := IsSwarmAPIControlled(test.profile)
		require.Equal(t, test.wantIsControlled, isControlled)
		require.Equal(t, test.wantAccess, access)
		require.Equal(t, test.wantErr, err)
	}
}

func TestAPIEntitlementOverrideRule(t *testing.T) {
	entitlementID := APIEntFullID

	apiEnt, ok := GetDefaultEntitlement(entitlementID)
	require.True(t, ok, fmt.Errorf("API entitlement not present"))

	ociProfile := secprofile.NewOCIProfile(testutils.TestSpec(), "test-profile")

	apiStrEnt, ok := apiEnt.(*entitlement.StringEntitlement)
	require.True(t, ok, fmt.Errorf("API entitlement is not a string entitlement"))

	testAPIIDStr := "foo"
	testAPIID := secprofile.APIID(testAPIIDStr)

	// Generate "foo:all:allow"
	testAPIAllowValue := fmt.Sprintf("%s:%s:%s", testAPIIDStr, APIFullControl, string(secprofile.Allow))

	// Generate "foo:all:deny"
	testAPIDenyValue := fmt.Sprintf("%s:%s:%s", testAPIIDStr, APIFullControl, string(secprofile.Deny))

	err := apiStrEnt.SetValue(testAPIAllowValue)
	require.NoError(t, err)

	refAPIRights := make(map[secprofile.APIID]map[secprofile.APISubsetID]secprofile.APIAccess)
	refAPIRights[testAPIID] = map[secprofile.APISubsetID]secprofile.APIAccess{
		secprofile.APISubsetID(APIFullControl): secprofile.Allow,
	}

	_, err = apiEnt.Enforce(ociProfile)
	require.NoError(t, err)

	// Check equality on API identifiers, API subset identifiers and API access rules
	require.True(t, reflect.DeepEqual(ociProfile.APIAccessConfig.APIRights, refAPIRights))

	err = apiStrEnt.SetValue(testAPIDenyValue)
	require.NoError(t, err)

	_, err = apiEnt.Enforce(ociProfile)
	require.NoError(t, err)

	refAPIRights[testAPIID][secprofile.APISubsetID(APIFullControl)] = secprofile.Deny

	// Check equality on API identifiers, API subset identifiers and API access rules
	require.True(t, reflect.DeepEqual(ociProfile.APIAccessConfig.APIRights, refAPIRights))
}
