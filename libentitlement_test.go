package libentitlement

import (
	"testing"
	entContext "github.com/docker/libentitlement/context"
	"github.com/docker/libentitlement/entitlement"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"fmt"
)

func TestRegisterDummyEntitlement(t *testing.T) {
	ctx := entContext.NewContext()
	entMgr := NewEntitlementsManager(ctx)

	// Add a dummy "foo.bar.cap-sys-admin" void entitlement that adds CAP_SYS_ADMIN
	capSysAdminVoidEntCallback := func (ctx *entContext.Context) (*entContext.Context, error) {
		if ctx == nil {
			return nil, fmt.Errorf("CapSysAdminVoidEntCallback - context is nil.")
		}
		capToAdd := "CAP_SYS_ADMIN"

		if ctx.Process == nil {
			ctx.Process = &specs.Process{}
		}

		if ctx.Process.Capabilities == nil {
			caps := []string{capToAdd}
			ctx.Process.Capabilities = &specs.LinuxCapabilities{
				Bounding: caps,
				Effective: caps,
				Permitted: caps,
				Inheritable: caps,
				Ambient: []string{},
			}
		} else {
			ctx.Process.Capabilities.Bounding = append(ctx.Process.Capabilities.Bounding, capToAdd)
			ctx.Process.Capabilities.Effective = append(ctx.Process.Capabilities.Effective, capToAdd)
			ctx.Process.Capabilities.Permitted = append(ctx.Process.Capabilities.Permitted, capToAdd)
			ctx.Process.Capabilities.Inheritable = append(ctx.Process.Capabilities.Inheritable, capToAdd)
		}

		return ctx, nil
	}

	capSysAdminVoidEntFullName := "foo-bar.meh.cap-sys-admin"

	capSysAdminVoidEnt := entitlement.NewVoidEntitlement(capSysAdminVoidEntFullName, capSysAdminVoidEntCallback)

	err := entMgr.Add(capSysAdminVoidEnt)
	require.NoError(t, err, "Entitlement %s should have been added and enforced", capSysAdminVoidEntFullName)

	require.Contains(t, ctx.Process.Capabilities.Bounding, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
	require.Contains(t, ctx.Process.Capabilities.Effective, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
	require.Contains(t, ctx.Process.Capabilities.Permitted, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
	require.Contains(t, ctx.Process.Capabilities.Inheritable, "CAP_SYS_ADMIN", "Capability is missing after entitlement enforcement")
}