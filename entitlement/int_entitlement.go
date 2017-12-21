package entitlement

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/moby/libentitlement/parser"
	"github.com/moby/libentitlement/secprofile"
)

// IntEntitlementEnforceCallback should take the security profile to update with the constraints and
// the entitlement int value as a parameter when being executed
type IntEntitlementEnforceCallback func(secprofile.Profile, int64) (secprofile.Profile, error)

// IntEntitlement is an entitlement with an explicit int value
type IntEntitlement struct {
	domain          []string
	id              string
	value           int64
	EnforceCallback IntEntitlementEnforceCallback
}

// NewIntEntitlement instantiates a new integer Entitlement
func NewIntEntitlement(fullName string, callback IntEntitlementEnforceCallback) Entitlement {
	domain, id, value, err := parser.ParseIntEntitlement(fullName)
	if err != nil {
		logrus.Errorf("Could not create int entitlement for %v", fullName)
		return nil
	}

	// FIXME: Add entitlement domain and the identifier to it
	return &IntEntitlement{domain: domain, id: id, value: value, EnforceCallback: callback}
}

// Domain returns the entitlement's domain name as a string
func (e *IntEntitlement) Domain() (string, error) {
	if len(e.domain) == 0 {
		id, err := e.Identifier()
		if err != nil {
			return "", fmt.Errorf("No domain or id found for current entitlement")
		}

		return "", fmt.Errorf("No domain found for entitlement %s", id)
	}

	return strings.Join(e.domain, "."), nil
}

// Identifier returns the entitlement's identifier
func (e *IntEntitlement) Identifier() (string, error) {
	if e.id == "" {
		return "", fmt.Errorf("No identifier found for current entitlement")
	}

	return e.id, nil
}

// Value returns the entitlement's value.
// Note: Int entitlements need an explicit value, it can't be an empty string
func (e *IntEntitlement) Value() (string, error) {
	strValue := strconv.FormatInt(e.value, 10)

	return strValue, nil
}

// Enforce calls the enforcement callback which applies the constraints on the security profile
// based on the entitlement int value
func (e *IntEntitlement) Enforce(profile secprofile.Profile) (secprofile.Profile, error) {
	if e.EnforceCallback == nil {
		id, _ := e.Identifier()
		domain, _ := e.Domain()
		return profile, fmt.Errorf("Invalid enforcement callback for entitlement %v.%v", domain, id)
	}

	newProfile, err := e.EnforceCallback(profile, e.value)
	if err != nil {
		return profile, err
	}

	return newProfile, err
}
