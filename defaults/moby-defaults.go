package defaults

import (
	"github.com/docker/libentitlement/types"
)

var (
	// MobyDefaultCaps is the default set of capabilities on Moby
	MobyDefaultCaps = map[types.Capability]bool{
		CapChown:          true,
		CapDacOverride:    true,
		CapFsetid:         true,
		CapFowner:         true,
		CapMknod:          true,
		CapNetRaw:         true,
		CapSetgid:         true,
		CapSetuid:         true,
		CapSetfcap:        true,
		CapSetpcap:        true,
		CapNetBindService: true,
		CapSysChroot:      true,
		CapKill:           true,
		CapAuditWrite:     true,
	}
)
