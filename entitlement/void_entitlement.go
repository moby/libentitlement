package entitlement

import (
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"

	"github.com/moby/libentitlement/parser"
	secprofile "github.com/moby/libentitlement/secprofile"
)

// VoidEntitlementEnforceCallback should take the security profile to update with the constraints
type VoidEntitlementEnforceCallback func(secprofile.Profile) (secprofile.Profile, error)

// VoidEntitlement is an entitlement without parameters
type VoidEntitlement struct {
	domain          []string
	id              string
	enforceCallback VoidEntitlementEnforceCallback
}

// NewVoidEntitlement instantiates a new VoidEntitlement
func NewVoidEntitlement(fullName string, callback VoidEntitlementEnforceCallback) *VoidEntitlement {
	domain, id, err := parser.ParseVoidEntitlement(fullName)
	if err != nil {
		logrus.Errorf("Couldn't not create entitlement for %v\n", fullName)
		return nil
	}

	return &VoidEntitlement{domain: domain, id: id, enforceCallback: callback}
}

// Domain returns the entitlement's domain name
func (e *VoidEntitlement) Domain() (string, error) {
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
func (e *VoidEntitlement) Identifier() (string, error) {
	if e.id == "" {
		return "", fmt.Errorf("No identifier found for current entitlement")
	}

	return e.id, nil
}

// Value should not be called on a void entitlement
func (e *VoidEntitlement) Value() (string, error) {
	return "", nil
}

// Enforce calls the enforcement callback which applies the constraints on the security profile
// based on the entitlement value
func (e *VoidEntitlement) Enforce(profile secprofile.Profile) (secprofile.Profile, error) {
	domain, _ := e.Domain()
	id, _ := e.Identifier()

	if e.enforceCallback == nil {
		return nil, fmt.Errorf("Invalid enforcement callback for entitlement %v.%v", domain, id)
	}

	newProfile, err := e.enforceCallback(profile)
	if err != nil {
		return nil, err
	}

	return newProfile, err
}
