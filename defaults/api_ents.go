package defaults

import (
	"fmt"
	"strings"

	"github.com/moby/libentitlement/entitlement"
	"github.com/moby/libentitlement/secprofile"

	"github.com/sirupsen/logrus"
)

const (
	// APIEntFullID is the API entitlement identifier; the value format is: "api.access:api-id:subset:[allow|deny]"
	// ex: "api.access:engine.v1_35.swarm:all:allow"
	APIEntFullID = "api.access"

	// APIFullControl specifies access control for the whole api
	APIFullControl = "all"
)

// Default known APIs and API subsets to control access of
const (
	// EngineAPI defines the Moby-Engine API
	EngineAPI = "engine"

	// SwarmAPI defines the Moby-Engine Swarm API
	SwarmAPI = "swarm"

	// Moby-Engine API Version
	EngineAPIVersion = "v1_35"
)

var (
	apiEntitlement = entitlement.NewStringEntitlement(APIEntFullID, apiEntitlementEnforce)
)

// GetSwarmAPIIdentifier returns the full Swarm API identifier
func GetSwarmAPIIdentifier() secprofile.APIID {
	return secprofile.APIID(fmt.Sprintf("%s.%s.%s", EngineAPI, EngineAPIVersion, SwarmAPI))
}

/*IsSwarmAPIControlled checks if Moby Swarm API is controlled and whether it's allowed or not
 * Return values are the following:
 * isControlled - if no error is encountered, whether the Swarm API is currently controlled by the entitlements
 * access - if Swarm API is currently controlled, this return value holds the allow/deny access requested
 * err - error returned if an issue is encountered
 */
func IsSwarmAPIControlled(profile secprofile.Profile) (isControlled bool, access secprofile.APIAccess, err error) {
	ociProfile, err := ociProfileConversionCheck(profile, APIEntFullID)
	if err != nil {
		return false, secprofile.Allow, err
	}

	if ociProfile.APIAccessConfig == nil {
		return false, secprofile.Allow, fmt.Errorf("OCI profile's APIAccess field nil")
	}

	swarmAPIFullID := GetSwarmAPIIdentifier()

	apiSubset, ok := ociProfile.APIAccessConfig.APIRights[swarmAPIFullID]
	if !ok || apiSubset == nil {
		return false, secprofile.Allow, nil
	}

	access, ok = apiSubset[APIFullControl]
	if !ok {
		return false, secprofile.Allow, nil
	}

	return true, access, nil
}

func apiEntitlementEnforce(profile secprofile.Profile, apiToAccess string) (secprofile.Profile, error) {
	logrus.Debugf("API entitlement for %s", apiToAccess)

	ociProfile, err := ociProfileConversionCheck(profile, APIEntFullID)
	if err != nil {
		return nil, err
	}

	if ociProfile.APIAccessConfig == nil {
		return nil, fmt.Errorf("OCI profile's APIAccess field nil")
	}

	apiToAccessFields := strings.Split(apiToAccess, ":")
	badAccessFormatError := fmt.Errorf("Wrong API subset and access format, should be \"api-id:subset:[allow|deny]\"")

	logrus.Debugf("Fields found for %s: %v", apiToAccess, apiToAccessFields)
	if len(apiToAccessFields) != 3 {
		return nil, badAccessFormatError
	}

	apiIDStr := apiToAccessFields[0]
	apiSubsetStr := apiToAccessFields[1]
	accessStr := apiToAccessFields[2]

	apiID := secprofile.APIID(apiIDStr)
	apiSubset := secprofile.APISubsetID(apiSubsetStr)
	access := secprofile.APIAccess(accessStr)

	switch access {
	case secprofile.Deny, secprofile.Allow:
		apiIDSubsets, ok := ociProfile.APIAccessConfig.APIRights[apiID]
		if !ok {
			ociProfile.APIAccessConfig.APIRights[apiID] = make(map[secprofile.APISubsetID]secprofile.APIAccess)
			apiIDSubsets = ociProfile.APIAccessConfig.APIRights[apiID]
		}

		apiIDSubsets[apiSubset] = access

		return ociProfile, nil
	}

	return nil, badAccessFormatError
}
