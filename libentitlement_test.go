package libentitlement

import (
	"testing"
	secprofile "github.com/docker/libentitlement/security-profile"
	"github.com/docker/libentitlement/entitlement"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"fmt"
)

func TestRegisterDummyEntitlement(t *testing.T) {
	profile := secprofile.NewProfile()
	entMgr := NewEntitlementsManager(profile)

	// Add a dummy "foo.bar.cap-sys-admin" void entitlement that adds CAP_SYS_ADMIN
	capSysAdminVoidEntCallback := func (profile *secprofile.Profile) (*secprofile.Profile, error) {
		if profile == nil {
			return nil, fmt.Errorf("CapSysAdminVoidEntCallback - profile is nil.")
		}
		capToAdd := "CAP_SYS_ADMIN"

		if profile.Process == nil {
			profile.Process = &specs.Process{}
		}

		if profile.Process.Capabilities == nil {
			caps := []string{capToAdd}
			profile.Process.Capabilities = &specs.LinuxCapabilities{
				Bounding: caps,
				Effective: caps,
				Permitted: caps,
				Inheritable: caps,
				Ambient: []string{},
			}
		} else {
			profile.Process.Capabilities.Bounding = append(profile.Process.Capabilities.Bounding, capToAdd)
			profile.Process.Capabilities.Effective = append(profile.Process.Capabilities.Effective, capToAdd)
			profile.Process.Capabilities.Permitted = append(profile.Process.Capabilities.Permitted, capToAdd)
			profile.Process.Capabilities.Inheritable = append(profile.Process.Capabilities.Inheritable, capToAdd)
		}

		return profile, nil
	}

	capSysAdminVoidEntFullName := "foo-bar.meh.cap-sys-admin"

	capSysAdminVoidEnt := entitlement.NewVoidEntitlement(capSysAdminVoidEntFullName, capSysAdminVoidEntCallback)

	err := entMgr.Add(capSysAdminVoidEnt)
	require.NoError(t, err, "Entitlement %s should have been added and enforced", capSysAdminVoidEntFullName)

	require.Contains(t, profile.Process.Capabilities.Bounding, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
	require.Contains(t, profile.Process.Capabilities.Effective, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
	require.Contains(t, profile.Process.Capabilities.Permitted, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
	require.Contains(t, profile.Process.Capabilities.Inheritable, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
}