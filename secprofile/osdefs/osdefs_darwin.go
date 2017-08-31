// +build darwin

package osdefs

const (
	// PrCapbsetDrop is prctl PR_CAPBSET_READ argument value
	PrCapbsetDrop = 0x18
	// PrCapbsetRead is prctl PR_CAPBSET_DROP argument value
	PrCapbsetRead = 0x17
)
