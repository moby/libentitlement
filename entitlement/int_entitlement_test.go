package entitlement

import (
	"fmt"
	"testing"
)

func TestIntEntitlementNoCallback(t *testing.T) {
	tests := map[Entitlement]*Result{
		NewIntEntitlement("", nil): nil,
		NewIntEntitlement("foo.x=1", nil): {
			Domain:     tuple{"foo", nil},
			Identifier: tuple{"x", nil},
			Value:      tuple{"1", nil},
			EnforceErr: fmt.Errorf("Invalid enforcement callback for entitlement foo.x"),
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
