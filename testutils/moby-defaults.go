package testutils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"runtime"

	"github.com/docker/libentitlement/secprofile/osdefs"
	"github.com/docker/libentitlement/types"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// mobyDefaultSeccompProfile is the default Seccomp profile on Moby
	mobyDefaultSeccompProfile = "seccomp_default.json"
)

var (
	// mobyDefaultCaps is the default set of capabilities on Moby
	mobyDefaultCaps = map[types.Capability]bool{
		osdefs.CapChown:          true,
		osdefs.CapDacOverride:    true,
		osdefs.CapFsetid:         true,
		osdefs.CapFowner:         true,
		osdefs.CapMknod:          true,
		osdefs.CapNetRaw:         true,
		osdefs.CapSetgid:         true,
		osdefs.CapSetuid:         true,
		osdefs.CapSetfcap:        true,
		osdefs.CapSetpcap:        true,
		osdefs.CapNetBindService: true,
		osdefs.CapSysChroot:      true,
		osdefs.CapKill:           true,
		osdefs.CapAuditWrite:     true,
	}
)

func getDefaultSeccompProfile() (*specs.LinuxSeccomp, error) {
	var profile specs.LinuxSeccomp

	_, currentPath, _, _ := runtime.Caller(0)

	fpath := filepath.Join(filepath.Dir(currentPath), mobyDefaultSeccompProfile)

	jsonProfile, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, fmt.Errorf("Reading test seccomp profile failed: %v", err)
	}

	err = json.Unmarshal(jsonProfile, &profile)
	if err != nil {
		return nil, fmt.Errorf("Decoding test seccomp profile failed: %v", err)
	}

	return &profile, nil
}

func getDefaultCapList() []string {
	capList := []string{}

	for capName := range mobyDefaultCaps {
		capList = append(capList, string(capName))
	}

	return capList
}

func getDefaultCapSet() map[types.Capability]bool {
	capSet := make(map[types.Capability]bool)

	for cap, val := range mobyDefaultCaps {
		capSet[cap] = val
	}

	return capSet
}

// GetNonDefaultMounts returns a mount set from the provided mount list without default Moby mounts that it may contain
func GetNonDefaultMounts(mountList []specs.Mount) []specs.Mount {
	defaultMountList := osdefs.DefaultMobyAllowedMounts

	nonDefaultMounts := []specs.Mount{}

	for _, mount := range mountList {
		found := false

		for _, defaultMount := range defaultMountList {
			if reflect.DeepEqual(defaultMount, mount) {
				found = true
				break
			}
		}

		if !found {
			nonDefaultMounts = append(nonDefaultMounts, mount)
		}
	}

	return nonDefaultMounts
}
