package defaults

import (
	"fmt"

	"github.com/docker/libentitlement/secprofile"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/docker/libentitlement/types"
	"reflect"
)

func capListContains(capList []string, capability types.Capability) bool {
	capStr := string(capability)

	for _, capElt := range capList {
		if capElt == capStr {
			return true
		}
	}

	return false
}

func ociProfileConversionCheck(profile secprofile.Profile, entitlementID string) (*secprofile.OCIProfile, error) {
	if profile.GetType() != secprofile.OCIProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", entitlementID)
	}

	ociProfile, ok := profile.(*secprofile.OCIProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", entitlementID)
	}

	return ociProfile, nil
}

// FIXME factor for all defaults package and even project-wide
func testSpec() *specs.Spec {
	s := &specs.Spec{
		Process: specs.Process{
			Capabilities: &specs.LinuxCapabilities{
				Bounding:    []string{},
				Effective:   []string{},
				Inheritable: []string{},
				Permitted:   []string{},
				Ambient:     []string{},
			},
		},
		Linux: &specs.Linux{
			Seccomp:   &specs.LinuxSeccomp{},
			Resources: &specs.LinuxResources{},
			IntelRdt:  &specs.LinuxIntelRdt{},
		},
		Windows: &specs.Windows{
			Resources: &specs.WindowsResources{
				Memory:  &specs.WindowsMemoryResources{},
				CPU:     &specs.WindowsCPUResources{},
				Storage: &specs.WindowsStorageResources{},
				Network: &specs.WindowsNetworkResources{},
			},
		},
	}

	return s
}

// We can't create a map to check set inclusion with specs.LinuxSeccompArg as key type in Golang so no O(n)
func seccompArgsContains(syscallArgsSet, syscallArgsSubset []specs.LinuxSeccompArg) bool {
	if len(syscallArgsSet) < len(syscallArgsSubset) {
		return false
	}

	for _, syscallArgFromSubset := range syscallArgsSubset {
		found := false

		for _, syscallArgsFromSet := range syscallArgsSet {
			if reflect.DeepEqual(syscallArgFromSubset, syscallArgsFromSet) {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

func matchSeccompRule(seccompRule specs.LinuxSyscall, syscallName string, syscallArgs []specs.LinuxSeccompArg) bool {
	for _, name := range seccompRule.Names {
		if name == syscallName {
			if seccompArgsContains(seccompRule.Args, syscallArgs) {
				return false
			}
		}
	}

	return true
}

func seccompSyscallWithArgsBlocked(seccompProfile specs.LinuxSeccomp, syscallName types.Syscall, syscallArgs []specs.LinuxSeccompArg) bool {
	syscallNameStr := string(syscallName)

	blocked := seccompProfile.DefaultAction == specs.ActErrno

	if blocked {
		// For each rule in the seccomp profile, make sure that no whitelisting rule contains this syscall
		for _, seccompRule := range seccompProfile.Syscalls {
			if seccompRule.Action == specs.ActAllow {
				// If we match a whitelisting rule containing this syscall and those arguments, syscall is not blocked
				if matchSeccompRule(seccompRule, syscallNameStr, syscallArgs) {
					return false
				}
			}
		}
	} else {
		// For each rule in the seccomp profile, make sure that at least one blacklisting rule contain this syscall
		for _, seccompRule := range seccompProfile.Syscalls {
			if seccompRule.Action == specs.ActErrno {
				// If we match a blacklisting rule containing this syscall and those arguments, syscall is blocked
				if matchSeccompRule(seccompRule, syscallNameStr, syscallArgs) {
					return true
				}
			}
		}
	}

	return blocked
}

func seccompSyscallsWithArgsBlocked(seccompProfile specs.LinuxSeccomp, syscallsWithArgs map[types.Syscall][]specs.LinuxSeccompArg) bool {
	for syscallName, syscallArgs := range syscallsWithArgs {
		if !seccompSyscallWithArgsBlocked(seccompProfile, syscallName, syscallArgs) {
			return false
		}
	}

	return true
}

func seccompSyscallsBlocked(seccompProfile specs.LinuxSeccomp, syscallNames []types.Syscall) bool {
	for _, syscallName := range syscallNames {
		if !seccompSyscallWithArgsBlocked(seccompProfile, syscallName, []specs.LinuxSeccompArg{}) {
			return false
		}
	}

	return true
}

func capBlocked(linuxCaps specs.LinuxCapabilities, capability types.Capability) bool {
	return !(capListContains(linuxCaps.Bounding, capability) || capListContains(linuxCaps.Permitted, capability) ||
		capListContains(linuxCaps.Inheritable, capability) || capListContains(linuxCaps.Effective, capability))
}

func capsBlocked(linuxCaps specs.LinuxCapabilities, capabilities []types.Capability) bool {
	for _, capability := range capabilities {
		if !capBlocked(linuxCaps, capability) {
			return false
		}
	}

	return true
}

func capAllowed(linuxCaps specs.LinuxCapabilities, capability types.Capability) bool {
	return capListContains(linuxCaps.Bounding, capability) && capListContains(linuxCaps.Permitted, capability) &&
		capListContains(linuxCaps.Inheritable, capability) && capListContains(linuxCaps.Effective, capability)
}

func capsAllowed(linuxCaps specs.LinuxCapabilities, capabilities []types.Capability) bool {
	for _, capability := range capabilities {
		if !capAllowed(linuxCaps, capability) {
			return false
		}
	}

	return true
}

func namespaceActivated(nsList []specs.LinuxNamespace, namespace specs.LinuxNamespaceType) bool {
	for _, ns := range nsList {
		if ns.Type == namespace {
			return true
		}
	}

	return false
}

func namespacesActivated(nsList []specs.LinuxNamespace, namespaces []specs.LinuxNamespaceType) bool {
	for _, namespace := range namespaces {
		if !namespaceActivated(nsList, namespace) {
			return false
		}
	}

	return true
}

func namespacesDeactivated(nsList []specs.LinuxNamespace, namespaces []specs.LinuxNamespaceType) bool {
	for _, namespace := range namespaces {
		if namespaceActivated(nsList, namespace) {
			return false
		}
	}

	return true
}