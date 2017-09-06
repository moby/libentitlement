package testutils

import (
	"github.com/docker/libentitlement/types"
	"github.com/opencontainers/runtime-spec/specs-go"
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

// TestSpec is a test OCI struct with a default Seccomp profile
func TestSpec() *specs.Spec {
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

	seccomp, err := getDefaultSeccompProfile()
	if err != nil {
		// In case we get an error before seccomp struct is fully updated from decoded json, we empty it manually.
		s.Linux.Seccomp = &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	} else {
		s.Linux.Seccomp = seccomp
	}

	s.Process.Capabilities.Bounding = getDefaultCapList()
	s.Process.Capabilities.Effective = getDefaultCapList()
	s.Process.Capabilities.Inheritable = getDefaultCapList()
	s.Process.Capabilities.Permitted = getDefaultCapList()

	return s
}

// areSyscallArgsMatchedBySeccompRuleArgs checks that the seccomp rule's args match the provided syscall args
func areSyscallArgsMatchedBySeccompRuleArgs(argsFromRule, argsFromSyscall []specs.LinuxSeccompArg) bool {
	if len(argsFromRule) < len(argsFromSyscall) ||
		(len(argsFromSyscall) == 0 && len(argsFromRule) != 0) {
		return false
	}

	for _, argFromSyscall := range argsFromSyscall {
		found := false

		for _, argFromRule := range argsFromRule {
			if reflect.DeepEqual(argFromSyscall, argFromRule) {
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

// syscallWithArgsMatchSeccompRule checks that the seccomp rule matches the provided syscall and args
func isSyscallWithArgsMatchedBySeccompRule(seccompRule specs.LinuxSyscall, syscallName string, syscallArgs []specs.LinuxSeccompArg) bool {
	for _, name := range seccompRule.Names {
		if name == syscallName {
			if areSyscallArgsMatchedBySeccompRuleArgs(seccompRule.Args, syscallArgs) {
				return true
			}
		}
	}

	return false
}

// isSyscallWithArgsBlockedBySeccomp checks that the provided syscall and args are blocked by the seccomp profile
func isSyscallWithArgsBlockedBySeccomp(seccompProfile specs.LinuxSeccomp, syscallName types.Syscall, syscallArgs []specs.LinuxSeccompArg) bool {
	syscallNameStr := string(syscallName)

	blocked := seccompProfile.DefaultAction == specs.ActErrno

	if blocked {
		// For each rule in the seccomp profile, make sure that no whitelisting rule contains this syscall
		for _, seccompRule := range seccompProfile.Syscalls {
			if seccompRule.Action == specs.ActAllow {
				// If we match a whitelisting rule containing this syscall and those arguments, syscall is not blocked
				if isSyscallWithArgsMatchedBySeccompRule(seccompRule, syscallNameStr, syscallArgs) {
					return false
				}
			}
		}
	} else {
		// For each rule in the seccomp profile, make sure that at least one blacklisting rule contain this syscall
		for _, seccompRule := range seccompProfile.Syscalls {
			if seccompRule.Action == specs.ActErrno {
				// If we match a blacklisting rule containing this syscall and those arguments, syscall is blocked
				if isSyscallWithArgsMatchedBySeccompRule(seccompRule, syscallNameStr, syscallArgs) {
					return true
				}
			}
		}
	}

	return blocked
}

// AreSyscallsWithArgsBlockedBySeccomp checks that the provided list of syscalls and args are blocked by the seccomp profile
func AreSyscallsWithArgsBlockedBySeccomp(seccompProfile specs.LinuxSeccomp, syscallsWithArgs map[types.Syscall][]specs.LinuxSeccompArg) bool {
	for syscallName, syscallArgs := range syscallsWithArgs {
		if !isSyscallWithArgsBlockedBySeccomp(seccompProfile, syscallName, syscallArgs) {
			return false
		}
	}

	return true
}

// AreSyscallsBlockedBySeccomp checks that the provided syscalls are blocked by the seccomp profile
func AreSyscallsBlockedBySeccomp(seccompProfile specs.LinuxSeccomp, syscallNames []types.Syscall) bool {
	for _, syscallName := range syscallNames {
		if !isSyscallWithArgsBlockedBySeccomp(seccompProfile, syscallName, []specs.LinuxSeccompArg{}) {
			return false
		}
	}

	return true
}

// isCapBlocked checks that the provided capability is not allowed
func isCapBlocked(linuxCaps specs.LinuxCapabilities, capability types.Capability) bool {
	return !(capListContains(linuxCaps.Bounding, capability) || capListContains(linuxCaps.Permitted, capability) ||
		capListContains(linuxCaps.Inheritable, capability) || capListContains(linuxCaps.Effective, capability))
}

// AreCapsBlocked checks that capabilities in the provided cap list are not allowed
func AreCapsBlocked(linuxCaps specs.LinuxCapabilities, capabilities []types.Capability) bool {
	for _, capability := range capabilities {
		if !isCapBlocked(linuxCaps, capability) {
			return false
		}
	}

	return true
}

// isCapAllowed checks that the provided capability is allowed
func isCapAllowed(linuxCaps specs.LinuxCapabilities, capability types.Capability) bool {
	return capListContains(linuxCaps.Bounding, capability) && capListContains(linuxCaps.Permitted, capability) &&
		capListContains(linuxCaps.Inheritable, capability) && capListContains(linuxCaps.Effective, capability)
}

// AreCapsAllowed checks that capabilities in the provided cap list are allowed
func AreCapsAllowed(linuxCaps specs.LinuxCapabilities, capabilities []types.Capability) bool {
	for _, capability := range capabilities {
		if !isCapAllowed(linuxCaps, capability) {
			return false
		}
	}

	return true
}

// capsListMatchRefSet checks that the cap list and the reference set contain the same capabilities
func capsListMatchRefSet(refWithConstraints map[types.Capability]bool, capList []string) bool {
	if len(refWithConstraints) != len(capList) {
		return false
	}

	refWithConstraintsStr := make(map[string]bool)
	for cap, val := range refWithConstraints {
		refWithConstraintsStr[string(cap)] = val
	}

	for _, cap := range capList {
		if _, ok := refWithConstraintsStr[cap]; !ok {
			return false
		}
	}

	return true
}

// capsListMatchRefWithConstraints checks that a provided list of capabilities matches exactly the content of
// the default capabilities plus a list of capabilities to add minus a list of capabilities to remove
func capsListMatchRefWithConstraints(capList []string, capsToAdd, capsToRemove []types.Capability) bool {
	refWithConstraints := getDefaultCapSet()

	for _, capToAdd := range capsToAdd {
		if _, ok := refWithConstraints[capToAdd]; !ok {
			refWithConstraints[capToAdd] = true
		}
	}

	for _, capToRemove := range capsToRemove {
		if _, ok := refWithConstraints[capToRemove]; ok {
			delete(refWithConstraints, capToRemove)
		}
	}

	return capsListMatchRefSet(refWithConstraints, capList)
}

// OCICapsMatchRefWithConstraints checks that all OCI capability lists match exactly the ref cap list with
// entitlement's constraints to apply.
func OCICapsMatchRefWithConstraints(capabilities specs.LinuxCapabilities, capsToAdd, capsToRemove []types.Capability) bool {
	capStrLists := [][]string{
		capabilities.Permitted,
		capabilities.Inheritable,
		capabilities.Effective,
		capabilities.Bounding,
	}

	match := true

	for _, capStrList := range capStrLists {
		match = match && capsListMatchRefWithConstraints(capStrList, capsToAdd, capsToRemove)
	}

	return match
}

// isNamespaceActived checks that the provided namespace is enabled
func isNamespaceActived(nsList []specs.LinuxNamespace, namespace specs.LinuxNamespaceType) bool {
	for _, ns := range nsList {
		if ns.Type == namespace {
			return true
		}
	}

	return false
}

// AreNamespacesActivated checks that the namespaces in the provided ns list are enabled
func AreNamespacesActivated(nsList []specs.LinuxNamespace, namespaces []specs.LinuxNamespaceType) bool {
	for _, namespace := range namespaces {
		if !isNamespaceActived(nsList, namespace) {
			return false
		}
	}

	return true
}

// AreNamespacesDeactivated checks that the namespaces in the provided ns list are disabled
func AreNamespacesDeactivated(nsList []specs.LinuxNamespace, namespaces []specs.LinuxNamespaceType) bool {
	for _, namespace := range namespaces {
		if isNamespaceActived(nsList, namespace) {
			return false
		}
	}

	return true
}
