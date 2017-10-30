package entitlement

import (
	"testing"

	"github.com/moby/libentitlement/secprofile"
	"github.com/stretchr/testify/require"
)

type tuple struct {
	Str string
	Err error
}

type Result struct {
	Domain, Identifier, Value tuple
	EnforceProfile            secprofile.Profile
	EnforceErr                error
}

func testEntitlement(t *testing.T, ent Entitlement, res *Result) {
	if ent == nil {
		require.Nil(t, res)
		return
	}
	r, err := ent.Domain()
	require.Equal(t, res.Domain.Str, r)
	require.Equal(t, res.Domain.Err, err)

	r, err = ent.Identifier()
	require.Equal(t, res.Identifier.Str, r)
	require.Equal(t, res.Identifier.Err, err)

	r, err = ent.Value()
	require.Equal(t, res.Value.Str, r)
	require.Equal(t, res.Value.Err, err)

	p, err := ent.Enforce(nil)
	require.Equal(t, res.EnforceProfile, p)
	require.Equal(t, res.EnforceErr, err)
}
