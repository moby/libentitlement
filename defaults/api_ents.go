package defaults

import (
	"fmt"
	"strings"

	"github.com/docker/libentitlement/entitlement"
	"github.com/docker/libentitlement/secprofile"
)

const (

	// api:engine.swarm=all:deny
	APIEntAllowID = "api:engine.swarm=all:allow"
	APIEntDenyID  = "api:engine.swarm=all:deny"
)

var (
	apiEntitlement = entitlement.NewStringEntitlement(APIEntAllowID, apiEntitlementEnforce)
	// TODO : Define stuff for the `deny` ID
)

func apiEntitlementEnforce(profile secprofile.Profile, apiSubsetAndAccess string) (secprofile.Profile, error) {
	fmt.Println("enforce called with", apiSubsetAndAccess)
	ociProfile, err := ociProfileConversionCheck(profile, NetworkNoneEntFullID)
	if err != nil {
		return nil, err
	}

	apiSubsetAndAccessFields := strings.Split(apiSubsetAndAccess, ":")

	fmt.Println("!! apiSubsetAndAccessFields", apiSubsetAndAccessFields)
	if len(apiSubsetAndAccessFields) != 3 {
		return nil, fmt.Errorf("Wrong API subset and access format, should be \"api-id:subset:[allow|deny]\"")
	}

	apiID := apiSubsetAndAccessFields[0]
	apiSubset := apiSubsetAndAccessFields[1]
	access := apiSubsetAndAccessFields[2]
	if access != string(secprofile.Allow) && access != string(secprofile.Deny) {
		return nil, fmt.Errorf("Wrong API subset and access format, should be \"api-id=subset:[allow|deny]\"")
	}

	if ociProfile.APIAccess == nil {
		return nil, fmt.Errorf("OCI profile's APIAccess field nil")
	}

	apiIDSubsets := ociProfile.APIAccess.APIRights[secprofile.APIID(apiID)]
	apiIDSubsets[secprofile.APISubsetID(apiSubset)] = secprofile.APIAccess(access)

	return ociProfile, nil
}
