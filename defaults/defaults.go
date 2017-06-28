package defaults

import "github.com/docker/libentitlement/entitlement"

var DefaultEntitlements = map[string]entitlement.Entitlement{
	NetworkNoneEntFullId:  entitlement.Entitlement(networkNoneEntitlement),
	NetworkUserEntFullId:  entitlement.Entitlement(networkUserEntitlement),
	NetworkProxyEntFullId: entitlement.Entitlement(networkProxyEntitlement),
	NetworkAdminEntFullId: entitlement.Entitlement(networkAdminEntitlement),
}
