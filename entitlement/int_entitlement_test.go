package entitlement

import (
	"fmt"
	"testing"

	"github.com/docker/libentitlement/secprofile"
)

func testIntEntitlementEnforce(profile secprofile.Profile, value int64) (secprofile.Profile, error) {
	if value != 1 {
		return nil, fmt.Errorf("Unexpected value passed to callback")
	}
	return profile, nil
}

func testIntEntitlementEnforceError(profile secprofile.Profile, value int64) (secprofile.Profile, error) {
	return nil, fmt.Errorf("An error occurred in the callback")
}

func TestIntEntitlementNoCallback(t *testing.T) {
	tests := map[Entitlement]*Result{
		NewIntEntitlement("", nil): nil,
		NewIntEntitlement("foo.x=1", nil): {
			Domain:     tuple{"foo", nil},
			Identifier: tuple{"x", nil},
			Value:      tuple{"1", nil},
			EnforceErr: fmt.Errorf("Invalid enforcement callback for entitlement foo.x"),
		},
		NewIntEntitlement("foo.x=1", testIntEntitlementEnforce): {
			Domain:     tuple{"foo", nil},
			Identifier: tuple{"x", nil},
			Value:      tuple{"1", nil},
		},
		NewIntEntitlement("foo.x=1", testIntEntitlementEnforceError): {
			Domain:     tuple{"foo", nil},
			Identifier: tuple{"x", nil},
			Value:      tuple{"1", nil},
			EnforceErr: fmt.Errorf("An error occurred in the callback"),
		},
		NewIntEntitlement("foo=a", nil):   nil,
		NewIntEntitlement("foo", nil):     nil,
		NewIntEntitlement("foo.x=a", nil): nil,
		NewIntEntitlement("foo.bar.x=1", nil): {
			Domain:     tuple{"foo.bar", nil},
			Identifier: tuple{"x", nil},
			Value:      tuple{"1", nil},
			EnforceErr: fmt.Errorf("Invalid enforcement callback for entitlement foo.bar.x"),
		},
	}

	for in, out := range tests {
		testEntitlement(t, in, out)
	}
}
