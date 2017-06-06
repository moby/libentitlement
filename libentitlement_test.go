package libentitlement

import (
	"fmt"
	"github.com/docker/libentitlement/entitlement"
	secprofile "github.com/docker/libentitlement/security-profile"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"testing"
)

func testSpec() *specs.Spec {
	s := &specs.Spec{
		Process: specs.Process{
			Capabilities: &specs.LinuxCapabilities{
				Bounding:    []string{},
				Effective:   []string{},
				Inheritable: []string{},
				Permitted:   []string{},
				Ambient:     []string{},
			},
		},
		Linux: &specs.Linux{
			Seccomp:   &specs.LinuxSeccomp{},
			Resources: &specs.LinuxResources{},
			IntelRdt:  &specs.LinuxIntelRdt{},
		},
		Windows: &specs.Windows{
			Resources: &specs.WindowsResources{
				Memory:  &specs.WindowsMemoryResources{},
				CPU:     &specs.WindowsCPUResources{},
				Storage: &specs.WindowsStorageResources{},
				Network: &specs.WindowsNetworkResources{},
			},
		},
	}

	return s
}

func TestRegisterDummyEntitlement(t *testing.T) {
	spec := testSpec()
	profile := secprofile.NewProfile(spec)

	entMgr := NewEntitlementsManager(profile)

	// Add a dummy "foo.bar.cap-sys-admin" void entitlement that adds CAP_SYS_ADMIN
	capSysAdminVoidEntCallback := func(profile *secprofile.Profile) (*secprofile.Profile, error) {
		if profile == nil {
			return nil, fmt.Errorf("CapSysAdminVoidEntCallback - profile is nil.")
		}

		profile.AddCaps("CAP_SYS_ADMIN")

		return profile, nil
	}

	capSysAdminVoidEntFullName := "foo-bar.meh.cap-sys-admin"

	capSysAdminVoidEnt := entitlement.NewVoidEntitlement(capSysAdminVoidEntFullName, capSysAdminVoidEntCallback)

	err := entMgr.Add(capSysAdminVoidEnt)
	require.NoError(t, err, "Entitlement %s should have been added and enforced", capSysAdminVoidEntFullName)

	require.Contains(t, profile.Oci.Process.Capabilities.Bounding, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
	require.Contains(t, profile.Oci.Process.Capabilities.Effective, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
	require.Contains(t, profile.Oci.Process.Capabilities.Permitted, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
	require.Contains(t, profile.Oci.Process.Capabilities.Inheritable, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
}
