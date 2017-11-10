package entitlement

import (
	"fmt"
	"testing"

	"github.com/moby/libentitlement/secprofile"
	"github.com/stretchr/testify/require"
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
		NewStringEntitlement("foo.x", nil): {
			Domain:     tuple{"foo", nil},
			Identifier: tuple{"x", nil},
			Value:      tuple{"", fmt.Errorf("Invalid value for entitlement foo.x")},
			EnforceErr: fmt.Errorf("Invalid value for entitlement foo.x"),
		},
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

func TestStringEntitlementSetValue(t *testing.T) {
	type test struct {
		entitlement Entitlement
		value       string
		wantValue   string
		wantErr     error
	}

	tests := []test{
		{
			entitlement: nil,
			value:       "",
			wantValue:   "",
			wantErr:     fmt.Errorf("Invalid entitlement"),
		},
		{
			entitlement: nil,
			value:       "test",
			wantValue:   "",
			wantErr:     fmt.Errorf("Invalid entitlement"),
		},
		{
			entitlement: NewStringEntitlement("test.foo", nil),
			value:       "",
			wantValue:   "",
			wantErr:     fmt.Errorf("Invalid value for entitlement test.foo"),
		},
		{
			entitlement: NewStringEntitlement("test.foo", nil),
			value:       "bar",
			wantValue:   "bar",
			wantErr:     nil,
		},
	}

	for _, tt := range tests {
		strEnt := (*StringEntitlement)(nil)
		if tt.entitlement != nil {
			ok := false
			strEnt, ok = tt.entitlement.(*StringEntitlement)
			require.True(t, ok)
		}

		err := strEnt.SetValue(tt.value)
		require.Equal(t, tt.wantErr, err)
		if tt.wantErr == nil && err == nil {
			require.Equal(t, tt.wantValue, strEnt.value)
		}
	}
}
