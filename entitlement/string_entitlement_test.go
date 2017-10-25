package entitlement

import (
	"fmt"
	"testing"

	"github.com/docker/libentitlement/secprofile"
)

// expectedStrEntitlementValue is the value our tests pass to the enforce
// callback after processing the entitlement ID string.
const expectedStrEntitlementValue = "baz"

func testStringEntitlementEnforce(profile secprofile.Profile, value string) (secprofile.Profile, error) {
	if value != expectedStrEntitlementValue {
		return nil, fmt.Errorf("Unexpected value passed to callback")
	}
	return profile, nil
}

func testStringEntitlementEnforceError(profile secprofile.Profile, value string) (secprofile.Profile, error) {
	return nil, fmt.Errorf("An error occurred in the callback")
}

func TestStringEntitlement(t *testing.T) {
	tests := map[Entitlement]*Result{
		NewStringEntitlement("", nil): nil,
		NewStringEntitlement("foo.bar=baz", nil): {
			Domain:     tuple{"foo", nil},
			Identifier: tuple{"bar", nil},
			Value:      tuple{expectedStrEntitlementValue, nil},
			EnforceErr: fmt.Errorf("Invalid enforcement callback for entitlement foo.bar"),
		},
		NewStringEntitlement("foo.bar=baz", testStringEntitlementEnforce): {
			Domain:     tuple{"foo", nil},
			Identifier: tuple{"bar", nil},
			Value:      tuple{expectedStrEntitlementValue, nil},
		},
		NewStringEntitlement("foo.bar=baz", testStringEntitlementEnforceError): {
			Domain:     tuple{"foo", nil},
			Identifier: tuple{"bar", nil},
			Value:      tuple{expectedStrEntitlementValue, nil},
			EnforceErr: fmt.Errorf("An error occurred in the callback"),
		},
		NewStringEntitlement("foo=a", nil): nil,
		NewStringEntitlement("foo", nil):   nil,
		NewStringEntitlement("foo.x", nil): nil,
		NewStringEntitlement("foo.bar.baz=qux", nil): {
			Domain:     tuple{"foo.bar", nil},
			Identifier: tuple{"baz", nil},
			Value:      tuple{"qux", nil},
			EnforceErr: fmt.Errorf("Invalid enforcement callback for entitlement foo.bar.baz"),
		},
	}

	for in, out := range tests {
		testEntitlement(t, in, out)
	}
}
