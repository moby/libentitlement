// +build linux

package osdefs

import "syscall"

const (
	// PrCapbsetDrop is prctl PR_CAPBSET_READ argument value
	PrCapbsetDrop = syscall.PR_CAPBSET_READ
	// PrCapbsetRead is prctl PR_CAPBSET_DROP argument value
	PrCapbsetRead = syscall.PR_CAPBSET_DROP
)
