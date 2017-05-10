package entitlement

import (
	"github.com/Sirupsen/logrus"
	"github.com/docker/libentitlement/context"
	"fmt"
	"strconv"
)

// Int entitlement's enforcement callback should take the security context to update with the constraints and
// the entitlement int value as a parameter when being executed
type IntEntitlementEnforceCallback func(*context.Context, int64) (*context.Context, error)

// Int entitlements are entitlements with an explicit int value
type IntEntitlement struct {
	domain string
	id string
	value []int64
	enforce_callback IntEntitlementEnforceCallback
}

// FIXME: implement regexp that matches domain-name.id=[numeric-value]
func intEntitlementParser(fullName string) (domain, id string, value int64, err error) {
	return domain, id, value, err
}

func NewIntEntitlement(fullName string, callback IntEntitlementEnforceCallback) *IntEntitlement {
	domain, id, value, err := intEntitlementParser(fullName)
	if err != nil {
		logrus.Errorf("Couldn't not create int entitlement for %v\n", fullName)
		return nil
	}

	valueRef := make([]int64, 1)
	valueRef[0] = value

	return &IntEntitlement{domain: domain, id: id, value: valueRef, enforce_callback:callback}
}

// Domain() returns the entitlement's domain name
func (e *IntEntitlement) Domain() (string, error) {
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
func (e *IntEntitlement) Identifier() (string, error) {
	if e.id == "" {
		return "", fmt.Errorf("No identifier found for current entitlement")
	}

	return e.id, nil
}

// Value() returns the entitlement's value.
// Note: Int entitlements need an explicit value, it can't be an empty string
func (e *IntEntitlement) Value() (string, error) {
	if e.value == nil || len(e.value) == 0 {
		id, _  := e.Identifier()
		domain, _ := e.Domain()
		return "", fmt.Errorf("Invalid value for entitlement %v.%v", domain, id)
	}

	strValue := strconv.FormatInt(int64(e.value[1]), 10)

	return strValue, nil
}

// Enforce() calls the enforcement callback which applies the constraints on the security context
// based on the entitlement int value
func (e *IntEntitlement) Enforce(ctx *context.Context) (*context.Context, error) {
	if e.value == nil || len(e.value) == 0 {
		id, _  := e.Identifier()
		domain, _ := e.Domain()
		return ctx, fmt.Errorf("Invalid value for entitlement %v.%v", domain, id)
	}

	if e.enforce_callback == nil {
		id, _  := e.Identifier()
		domain, _ := e.Domain()
		return ctx, fmt.Errorf("Invalid enforcement callback for entitlement %v.%v", domain, id)
	}

	newContext, err := e.enforce_callback(ctx, e.value[1])
	if err != nil {
		return ctx, err
	}

	return newContext, err
}



