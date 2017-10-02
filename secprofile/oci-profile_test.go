package secprofile

import (
	"reflect"
	"testing"

	"github.com/docker/libentitlement/secprofile/osdefs"
	"github.com/docker/libentitlement/testutils"
	"github.com/docker/libentitlement/types"
	"github.com/stretchr/testify/require"
)

func TestAlreadyPresentSyscall(t *testing.T) {
	testSyscall := osdefs.SysExit
	ociProfile := NewOCIProfile(testutils.TestSpec(), "test-profile")

	require.NotNil(t, ociProfile.OCI)
	require.NotNil(t, ociProfile.OCI.Linux)
	require.NotNil(t, ociProfile.OCI.Linux.Seccomp)

	syscalls := []types.Syscall{testSyscall}
	ociProfile.AllowSyscalls(syscalls...)

	seccompProfileWithTestSys := *ociProfile.OCI.Linux.Seccomp

	ociProfile.AllowSyscalls(syscalls...)
	didAdd := reflect.DeepEqual(seccompProfileWithTestSys, *ociProfile.OCI.Linux.Seccomp)
	require.True(t, didAdd, "Syscall was not already added to the seccomp profile")
}
