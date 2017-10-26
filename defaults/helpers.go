package defaults

import (
	"fmt"

	"github.com/moby/libentitlement/secprofile"
)

func ociProfileConversionCheck(profile secprofile.Profile, entitlementID string) (*secprofile.OCIProfile, error) {
	if profile.GetType() != secprofile.OCIProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", entitlementID)
	}

	ociProfile, ok := profile.(*secprofile.OCIProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", entitlementID)
	}

	return ociProfile, nil
}
