package entitlement

import (
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"

	"github.com/moby/libentitlement/parser"
	secprofile "github.com/moby/libentitlement/secprofile"
)

// StringEntitlementEnforceCallback should take the security profile to update with the constraints and
// the entitlement value as a parameter when being executed
type StringEntitlementEnforceCallback func(secprofile.Profile, string) (secprofile.Profile, error)

// StringEntitlement is an entitlements with an explicit string value
type StringEntitlement struct {
	domain          []string
	id              string
	value           string
	enforceCallback StringEntitlementEnforceCallback
}

// NewStringEntitlement instantiates a new string Entitlement
func NewStringEntitlement(fullName string, callback StringEntitlementEnforceCallback) Entitlement {
	domain, id, value, err := parser.ParseStringEntitlement(fullName)
	if err != nil {
		logrus.Errorf("Could not create string entitlement for %v\n", fullName)
		return nil
	}

	return &StringEntitlement{domain: domain, id: id, value: value, enforceCallback: callback}
}

// Domain returns the entitlement's domain name
func (e *StringEntitlement) Domain() (string, error) {
	if len(e.domain) < 1 {
		id, err := e.Identifier()
		if err != nil {
			return "", fmt.Errorf("No domain or id found for current entitlement")
		}

		return "", fmt.Errorf("No domain found for entitlement %s", id)
	}

	return strings.Join(e.domain, "."), nil
}

// Identifier returns the entitlement's identifier
func (e *StringEntitlement) Identifier() (string, error) {
	if e.id == "" {
		return "", fmt.Errorf("No identifier found for current entitlement")
	}

	return e.id, nil
}

// Value returns the entitlement's value.
// Note: String entitlements need an explicit value, it can't be an empty string
func (e *StringEntitlement) Value() (string, error) {
	if e.value == "" {
		id, _ := e.Identifier()
		domain, _ := e.Domain()
		return "", fmt.Errorf("Invalid value for entitlement %v.%v", domain, id)
	}

	return e.value, nil
}

// Enforce calls the enforcement callback which applies the constraints on the security profile
// based on the entitlement value
func (e *StringEntitlement) Enforce(profile secprofile.Profile) (secprofile.Profile, error) {
	value, err := e.Value()
	if err != nil {
		return nil, err
	}

	if e.enforceCallback == nil {
		id, _ := e.Identifier()
		domain, _ := e.Domain()
		return nil, fmt.Errorf("Invalid enforcement callback for entitlement %v.%v", domain, id)
	}

	newProfile, err := e.enforceCallback(profile, value)
	if err != nil {
		return nil, err
	}

	return newProfile, err
}
