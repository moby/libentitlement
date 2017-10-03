package entitlement

import (
	"fmt"
	"testing"
)

func TestStringEntitlementNoCallback(t *testing.T) {
	tests := map[Entitlement]*Result{
		NewStringEntitlement("", nil): nil,
		NewStringEntitlement("foo.bar=baz", nil): {
			Domain:     tuple{"foo", nil},
			Identifier: tuple{"bar", nil},
			Value:      tuple{"baz", nil},
			EnforceErr: fmt.Errorf("Invalid enforcement callback for entitlement foo.x"),
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
