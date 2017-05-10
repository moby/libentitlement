package entitlement

import (
	"github.com/Sirupsen/logrus"
	"github.com/docker/libentitlement/context"
	"fmt"
)

// String entitlement's enforcement callback should take the security context to update with the constraints and
// the entitlement value as a parameter when being executed
type StringEntitlementEnforceCallback func(*context.Context, string) (*context.Context, error)

// String entitlements are entitlements with an explicit string value
type StringEntitlement struct {
	domain string
	id string
	value string
	enforce_callback StringEntitlementEnforceCallback
}

// FIXME: implement regexp that matches domain-name.id=[stringvalue]
func stringEntitlementParser(fullName string) (domain, id, value string, err error) {
	return domain, id, value, err
}

func NewStringEntitlement(fullName string, callback StringEntitlementEnforceCallback) *StringEntitlement {
	domain, id, value, err := stringEntitlementParser(fullName)
	if err != nil {
		logrus.Errorf("Couldn't not create string entitlement for %v\n", fullName)
		return nil
	}

	return &StringEntitlement{domain: domain, id: id, value: value, enforce_callback:callback}
}

// Domain() returns the entitlement's domain name
func (e *StringEntitlement) Domain() (string, error) {
	if e.domain == "" {
		id, err := e.Identifier()
		if err != nil {
			return "", fmt.Errorf("No domain or id found for current entitlement")
		}

		return "", fmt.Errorf("No domain found for entitlement %s", id)
	}

	return e.domain, nil
}

// Identifier() returns the entitlement's identifier
func (e *StringEntitlement) Identifier() (string, error) {
	if e.id == "" {
		return "", fmt.Errorf("No identifier found for current entitlement")
	}

	return e.id, nil
}

// Value() returns the entitlement's value.
// Note: String entitlements need an explicit value, it can't be an empty string
func (e *StringEntitlement) Value() (string, error) {
	if e.value == "" {
		id, _  := e.Identifier()
		domain, _ := e.Domain()
		return "", fmt.Errorf("Invalid value for entitlement %v.%v", domain, id)
	}

	return e.value, nil
}

// Enforce() calls the enforcement callback which applies the constraints on the security context
// based on the entitlement value
func (e *StringEntitlement) Enforce(ctx *context.Context) (*context.Context, error) {
	value, err := e.Value()
	if err != nil {
		return nil, err
	}

	if e.enforce_callback == nil {
		id, _  := e.Identifier()
		domain, _ := e.Domain()
		return nil, fmt.Errorf("Invalid enforcement callback for entitlement %v.%v", domain, id)
	}

	newContext, err := e.enforce_callback(ctx, value)
	if err != nil {
		return nil, err
	}

	return newContext, err
}



