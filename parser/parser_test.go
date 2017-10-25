package parser

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseVoidEntitlement(t *testing.T) {
	testCases := []struct {
		input          string
		expectedDomain []string
		expectedID     string
		expectedErr    error
	}{
		{
			input:          "foo.bar",
			expectedDomain: []string{"foo"},
			expectedID:     "bar",
		},
		{
			input:          "foo.bar.baz",
			expectedDomain: []string{"foo", "bar"},
			expectedID:     "baz",
		},
		{
			input:          "bar",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedErr:    fmt.Errorf("Parsing of entitlement bar failed: either domain or id missing"),
		},
		{
			input:          "@#$.bar",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedErr:    fmt.Errorf("Parsing of entitlement @#$.bar failed: domain must be alphanumeric and can contain '-'. '.' is a domain separator"),
		},
		{
			input:          "foo.@#$",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedErr:    fmt.Errorf("Parsing of entitlement foo.@#$ failed: identifier must be alphanumeric and can contain '-'"),
		},
	}

	for _, tc := range testCases {
		domain, id, err := ParseVoidEntitlement(tc.input)
		require.Equal(t, tc.expectedDomain, domain)
		require.Equal(t, tc.expectedID, id)
		require.Equal(t, tc.expectedErr, err)
	}
}
func TestParseIntEntitlement(t *testing.T) {
	testCases := []struct {
		input          string
		expectedDomain []string
		expectedID     string
		expectedValue  int64
		expectedErr    error
	}{
		{
			input:          "foo.x=1",
			expectedDomain: []string{"foo"},
			expectedID:     "x",
			expectedValue:  1,
		},
		{
			input:          "foo.bar.x=1",
			expectedDomain: []string{"foo", "bar"},
			expectedID:     "x",
			expectedValue:  1,
		},
		{
			input:          "x=1",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedValue:  0,
			expectedErr:    fmt.Errorf("Parsing of int entitlement x=1 failed: either domain or id missing"),
		},
		{
			input:          "@#$.x=1",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedValue:  0,
			expectedErr:    fmt.Errorf("Parsing of int entitlement @#$.x=1 failed: domain must be alphanumeric and can contain '-'. '.' is a domain separator"),
		},
		{
			input:          "foo.x1",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedValue:  0,
			expectedErr:    fmt.Errorf("Parsing of int entitlement foo.x1 failed: format required 'domain-name.identifier=int-value'"),
		},
		{
			input:          "foo.@#$=1",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedValue:  0,
			expectedErr:    fmt.Errorf("Parsing of int entitlement foo.@#$=1 failed: identifier must be alphanumeric and can contain '-'"),
		},
		{
			input:          "foo.x=abc",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedValue:  0,
			expectedErr:    fmt.Errorf("Parsing of int entitlement foo.x=abc failed: entitlement argument must be a 64bits integer"),
		},
	}

	for _, tc := range testCases {
		domain, id, value, err := ParseIntEntitlement(tc.input)
		require.Equal(t, tc.expectedDomain, domain)
		require.Equal(t, tc.expectedID, id)
		require.Equal(t, tc.expectedValue, value)
		require.Equal(t, tc.expectedErr, err)
	}
}

func TestParseStringEntitlement(t *testing.T) {
	testCases := []struct {
		input          string
		expectedDomain []string
		expectedID     string
		expectedValue  string
		expectedErr    error
	}{
		{
			input:          "foo.bar=baz",
			expectedDomain: []string{"foo"},
			expectedID:     "bar",
			expectedValue:  "baz",
		},
		{
			input:          "foo.bar.baz=qux",
			expectedDomain: []string{"foo", "bar"},
			expectedID:     "baz",
			expectedValue:  "qux",
		},
		{
			input:          "bar=baz",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedValue:  "",
			expectedErr:    fmt.Errorf("Parsing of string entitlement bar=baz failed: either domain or id missing"),
		},
		{
			input:          "@#$.bar=baz",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedValue:  "",
			expectedErr:    fmt.Errorf("Parsing of string entitlement @#$.bar=baz failed: domain must be alphanumeric and can contain '-'. '.' is a domain separator"),
		},
		{
			input:          "foo.bar",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedValue:  "",
			expectedErr:    fmt.Errorf("Parsing of string entitlement foo.bar failed: format required 'domain-name.identifier=param'"),
		},
		{
			input:          "foo.@#$=baz",
			expectedDomain: []string(nil),
			expectedID:     "",
			expectedValue:  "",
			expectedErr:    fmt.Errorf("Parsing of string entitlement foo.@#$=baz failed: identifier must be alphanumeric and can contain '-'"),
		},
	}

	for _, tc := range testCases {
		domain, id, value, err := ParseStringEntitlement(tc.input)
		require.Equal(t, tc.expectedDomain, domain)
		require.Equal(t, tc.expectedID, id)
		require.Equal(t, tc.expectedValue, value)
		require.Equal(t, tc.expectedErr, err)
	}
}
