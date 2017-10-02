package testutils

import (
	"sort"
	"testing"

	"github.com/docker/libentitlement/secprofile/osdefs"
	"github.com/stretchr/testify/require"
)

func TestPathListMatchRefMount(t *testing.T) {
	refMounts := osdefs.DefaultMobyAllowedMounts

	mountPathsReverse := make([]string, len(refMounts))
	for index, mount := range refMounts {
		mountPathsReverse[index] = mount.Destination
	}

	// We test for a reverse version of the list, PathListMatchRefMount should still work
	sort.Sort(sort.Reverse(sort.StringSlice(mountPathsReverse)))

	require.True(t, PathListMatchRefMount(mountPathsReverse, refMounts), "Mount destination list and ref mount list should match.")

	// Cut the last element and test again, should fail
	mountPathsReverseWithoutLast := mountPathsReverse[:len(mountPathsReverse)-1]
	require.False(t, PathListMatchRefMount(mountPathsReverseWithoutLast, refMounts), "Mount destination list and ref mount list should not match.")
}
