package entitlement

import (
	"github.com/docker/libentitlement/context"
)

// FIXME: we should have several types of entitlements & a hierarchy in domain
// names (domain name system style implementation)
// ex:
// "Void entitlements": host.device.viewer
// "String array entitlements": (can hold single/multiple string/int values)
type Entitlement interface {
	// Entitlement's domain name (ex: network, host.devices,
	Domain() (string, error)
	// Entitlement's identifier
	Identifier() (string, error)
	// Entitlement value (eg. resources) - optional
	Value() (string, error)
	// Enforce should return an updated value of the context according to
	// the entitlement spec (FIXME: write a proper entitlement spec and link it in the proposal)
	Enforce(*context.Context) (*context.Context, error)
}
