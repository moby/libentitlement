package defaults

import "github.com/docker/libentitlement/entitlement"

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
}
