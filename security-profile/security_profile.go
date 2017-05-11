package context

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Context contains both some OCI spec settings
// Fixme add api access settings for Engine / Swarm / K8s?
// We should maintain container's relevant security context for both Linux and Windows.
type Context specs.Spec

func NewContext() *Context {
	return &Context{}
}
