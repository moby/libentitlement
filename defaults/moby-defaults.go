package defaults

var (
	MobyDefaultCaps = map[string]bool{
		CapChown:            true,
		CapDacOverride:     true,
		CapFsetid:           true,
		CapFowner:           true,
		CapMknod:            true,
		CapNetRaw:          true,
		CapSetgid:           true,
		CapSetuid:           true,
		CapSetfcap:          true,
		CapSetpcap:          true,
		CapNetBindService: true,
		CapSysChroot:       true,
		CapKill:             true,
		CapAuditWrite:      true,
	}
)