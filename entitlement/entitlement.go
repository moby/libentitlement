package entitlement

import (
	secprofile "github.com/docker/libentitlement/security-profile"
)

// FIXME: we should have a hierarchy in domains
// names (domain name system style implementation)
// ex:
// "Void entitlements": host.device.viewer
// "String array entitlements": (can hold single/multiple string/int values)

// FIXME: create error objects
// FIXME: add a method to return domain as a list and one as a string (currently string only)
type Entitlement interface {
	// Entitlement's domain name (ex: network, host.devices,
	Domain() (string, error)
	// Entitlement's identifier
	Identifier() (string, error)
	// Entitlement value (eg. resources) - optional
	Value() (string, error)
	// Enforce should return an updated value of the profile according to
	// the entitlement spec (FIXME: write a proper entitlement spec and link it in the proposal)
	Enforce(*secprofile.Profile) (*secprofile.Profile, error)
}
