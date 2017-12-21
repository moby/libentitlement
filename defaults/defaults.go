package defaults

import (
	"github.com/moby/libentitlement/entitlement"
)

// DefaultEntitlements are the pre-defined entitlements to be consumed by default from libentitlement
var DefaultEntitlements = map[string]entitlement.Entitlement{
	NetworkNoneEntFullID:  entitlement.Entitlement(networkNoneEntitlement),
	NetworkUserEntFullID:  entitlement.Entitlement(networkUserEntitlement),
	NetworkProxyEntFullID: entitlement.Entitlement(networkProxyEntitlement),
	NetworkAdminEntFullID: entitlement.Entitlement(networkAdminEntitlement),

	SecurityConfinedEntFullID: entitlement.Entitlement(securityConfinedEntitlement),
	SecurityViewEntFullID:     entitlement.Entitlement(securityViewEntitlement),
	SecurityAdminEntFullID:    entitlement.Entitlement(securityAdminEntitlement),
	SecurityMemoryLockFullID:  entitlement.Entitlement(securityMemoryLockEntitlement),

	HostDevicesNoneEntFullID:  entitlement.Entitlement(hostDevicesNoneEntitlement),
	HostDevicesViewEntFullID:  entitlement.Entitlement(hostDevicesViewEntitlement),
	HostDevicesAdminEntFullID: entitlement.Entitlement(hostDevicesAdminEntitlement),

	HostProcessesNoneEntFullID:  entitlement.Entitlement(hostProcessesNoneEntitlement),
	HostProcessesAdminEntFullID: entitlement.Entitlement(hostProcessesAdminEntitlement),

	APIEntFullID: entitlement.Entitlement(apiEntitlement),
}

// GetDefaultEntitlement returns a copy of a default entitlement (first return value) if present (second return value)
func GetDefaultEntitlement(entFullID string) (entitlement.Entitlement, bool) {
	ent, ok := DefaultEntitlements[entFullID]
	if !ok {
		return nil, false
	}

	return ent, true
}
