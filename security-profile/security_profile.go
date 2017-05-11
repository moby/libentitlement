package security_profile

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Profile contains both some OCI spec settings
// Fixme add api access settings for Engine / Swarm / K8s?
// We should maintain container's relevant security profile for both Linux and Windows.
type Profile specs.Spec

func NewProfile() *Profile {
	return &Profile{}
}
