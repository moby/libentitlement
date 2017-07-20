package secprofile

import (
	"github.com/docker/libentitlement/apparmor"
	"github.com/docker/libentitlement/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"reflect"
)

// OCIProfileType is an identifier for an OCI profile
var OCIProfileType = ProfileType("oci-profile")

// OCIProfile maintains some OCI spec settings but should also contain a complete security
// context.
// OCIProfile should be maintained for both Linux and Windows at any given time.
// FIXME: Add error handling here if profile or subfields are not allocated */
// Fixme add api access settings for Engine / Swarm / K8s?
type OCIProfile struct {
	OCI           *specs.Spec
	AppArmorSetup *apparmor.ProfileData
}

// NewOCIProfile instantiates an OCIProfile object with an OCI specification structure
func NewOCIProfile(ociSpec *specs.Spec, apparmorProfileName string) *OCIProfile {
	return &OCIProfile{OCI: ociSpec, AppArmorSetup: apparmor.NewProfileData(apparmorProfileName)}
}

// GetType returns the OCI profile type identifier
func (p *OCIProfile) GetType() ProfileType {
	return OCIProfileType
}

// AddCaps adds a list of capabilities if not present to all capability masks
func (p *OCIProfile) AddCaps(capsToAdd ...types.Capability) {
	for _, cap := range capsToAdd {
		capStr := string(cap)

		p.OCI.Process.Capabilities.Bounding = addCapToList(p.OCI.Process.Capabilities.Bounding, capStr)
		p.OCI.Process.Capabilities.Effective = addCapToList(p.OCI.Process.Capabilities.Effective, capStr)
		p.OCI.Process.Capabilities.Inheritable = addCapToList(p.OCI.Process.Capabilities.Inheritable, capStr)
		p.OCI.Process.Capabilities.Permitted = addCapToList(p.OCI.Process.Capabilities.Permitted, capStr)

		// Should be updated automatically if the previous masks are set
		p.OCI.Process.Capabilities.Ambient = addCapToList(p.OCI.Process.Capabilities.Ambient, capStr)
	}
}

// RemoveCaps removes a list of capabilities if present from all capability masks
func (p *OCIProfile) RemoveCaps(capsToRemove ...types.Capability) {
	for _, cap := range capsToRemove {
		capStr := string(cap)

		p.OCI.Process.Capabilities.Bounding = removeCapFromList(p.OCI.Process.Capabilities.Bounding, capStr)
		p.OCI.Process.Capabilities.Effective = removeCapFromList(p.OCI.Process.Capabilities.Effective, capStr)
		p.OCI.Process.Capabilities.Inheritable = removeCapFromList(p.OCI.Process.Capabilities.Inheritable, capStr)
		p.OCI.Process.Capabilities.Permitted = removeCapFromList(p.OCI.Process.Capabilities.Permitted, capStr)

		// Should be updated automatically if the previous masks are set
		p.OCI.Process.Capabilities.Ambient = removeCapFromList(p.OCI.Process.Capabilities.Ambient, capStr)
	}
}

// AddMaskedPaths adds a list of paths to the set of paths masked in the container if not present yet
func (p *OCIProfile) AddMaskedPaths(pathsToMask ...string) {
	for _, dir := range pathsToMask {
		exists := false
		for _, paths := range p.OCI.Linux.MaskedPaths {
			if paths == dir {
				exists = true
				break
			}
		}

		if !exists {
			p.OCI.Linux.MaskedPaths = append(p.OCI.Linux.MaskedPaths, dir)
		}
	}
}

// AddNamespaces adds a list of namespaces to the enabled namespaces
func (p *OCIProfile) AddNamespaces(nsTypes ...specs.LinuxNamespaceType) {
	for _, ns := range nsTypes {
		exists := false
		for _, namespace := range p.OCI.Linux.Namespaces {
			if namespace.Type == ns {
				exists = true
				break
			}
		}

		if !exists {
			newNs := specs.LinuxNamespace{Type: ns}
			p.OCI.Linux.Namespaces = append(p.OCI.Linux.Namespaces, newNs)
		}
	}
}

// RemoveNamespaces disables a list of namespaces
func (p *OCIProfile) RemoveNamespaces(nsTypes ...specs.LinuxNamespaceType) {
	for _, ns := range nsTypes {
		for index, namespace := range p.OCI.Linux.Namespaces {
			if namespace.Type == ns {
				p.OCI.Linux.Namespaces = append(p.OCI.Linux.Namespaces[:index], p.OCI.Linux.Namespaces[index+1:]...)
			}
		}
	}
}

// AllowSyscallsWithArgs adds seccomp rules to allow syscalls with the given arguments if necessary
func (p *OCIProfile) AllowSyscallsWithArgs(syscallsWithArgsToAllow map[types.Syscall][]specs.LinuxSeccompArg) {
	defaultActError := p.OCI.Linux.Seccomp.DefaultAction == specs.ActErrno

	for syscallNameToAllow, syscallArgsToAllow := range syscallsWithArgsToAllow {
		syscallNameToAllowStr := string(syscallNameToAllow)

		for _, syscallRule := range p.OCI.Linux.Seccomp.Syscalls {

			if syscallRule.Action == specs.ActAllow {
				for _, syscallName := range syscallRule.Names {
					if syscallName == syscallNameToAllowStr &&
						((len(syscallArgsToAllow) == 0 && len(syscallRule.Args) == 0) ||
							reflect.DeepEqual(syscallRule.Args, syscallArgsToAllow)) {
						return
					}
				}
			}
		}

		if defaultActError {
			newRule := specs.LinuxSyscall{
				Names:  []string{syscallNameToAllowStr},
				Action: specs.ActAllow,
				Args:   syscallArgsToAllow,
			}
			p.OCI.Linux.Seccomp.Syscalls = append(p.OCI.Linux.Seccomp.Syscalls, newRule)
		}
	}
}

// AllowSyscalls adds seccomp rules to allow a list of syscalls without specific arguments
func (p *OCIProfile) AllowSyscalls(syscallsToAllow ...types.Syscall) {
	syscallsWithNoArgsToAllow := make(map[types.Syscall][]specs.LinuxSeccompArg)
	for _, syscallsToAllow := range syscallsToAllow {
		syscallsWithNoArgsToAllow[syscallsToAllow] = []specs.LinuxSeccompArg{}
	}

	p.AllowSyscallsWithArgs(syscallsWithNoArgsToAllow)
}

// BlockSyscallsWithArgs adds seccomp rules to block syscalls with the given arguments and remove them from allowed/debug rules if present
func (p *OCIProfile) BlockSyscallsWithArgs(syscallsWithArgsToBlock map[types.Syscall][]specs.LinuxSeccompArg) {
	defaultActError := p.OCI.Linux.Seccomp.DefaultAction == specs.ActErrno

	/* For each syscall to block we browse each syscall list of each Seccomp rule */
	for syscallNameToBlock, syscallArgsToBlock := range syscallsWithArgsToBlock {
		blocked := false
		syscallNameToBlockStr := string(syscallNameToBlock)

		for syscallRuleIndex, syscallRule := range p.OCI.Linux.Seccomp.Syscalls {

			switch syscallRule.Action {
			case specs.ActAllow, specs.ActTrace, specs.ActTrap:
				for syscallNameIndex, syscallName := range syscallRule.Names {
					/* We found the syscall in the syscall list in a rule and arguments are identical */
					if syscallName == syscallNameToBlockStr &&
						((len(syscallArgsToBlock) == 0 && len(syscallRule.Args) == 0) ||
							reflect.DeepEqual(syscallRule.Args, syscallArgsToBlock)) {

						/* If this is the only one, just remove that rule from the Seccomp config */
						if len(p.OCI.Linux.Seccomp.Syscalls[syscallRuleIndex].Names) == 1 {
							p.OCI.Linux.Seccomp.Syscalls = append(
								p.OCI.Linux.Seccomp.Syscalls[0:syscallRuleIndex],
								p.OCI.Linux.Seccomp.Syscalls[syscallRuleIndex+1:]...,
							)

							break
						}

						/* Otherwise, remove it from the rule */
						p.OCI.Linux.Seccomp.Syscalls[syscallRuleIndex].Names = append(
							p.OCI.Linux.Seccomp.Syscalls[syscallRuleIndex].Names[0:syscallNameIndex],
							p.OCI.Linux.Seccomp.Syscalls[syscallRuleIndex].Names[syscallNameIndex+1:]...,
						)
					}
				}

			case specs.ActErrno, specs.ActKill:
				for _, syscallName := range syscallRule.Names {
					/* We found the syscall in the syscall list in a rule */
					if syscallName == syscallNameToBlockStr {
						blocked = true

						/* We'll keep looking in next rules outside of this loop as
						 * SECCOMP_RET_TRAP has precedence over SECCOMP_RET_ERRNO for example
						 * and we want to make sure we remove all those occurrences
						 */
						break
					}
				}
			}
		}

		/* If we don't find it in a blocking rule, we add one */
		if !blocked && !defaultActError {
			newRule := specs.LinuxSyscall{
				Names:  []string{syscallNameToBlockStr},
				Action: specs.ActErrno,
				Args:   syscallArgsToBlock,
			}
			p.OCI.Linux.Seccomp.Syscalls = append(p.OCI.Linux.Seccomp.Syscalls, newRule)
		}

	}
}

// BlockSyscalls blocks a list of syscalls without specific arguments
func (p *OCIProfile) BlockSyscalls(syscallsToBlock ...types.Syscall) {
	syscallsWithNoArgsToBlock := make(map[types.Syscall][]specs.LinuxSeccompArg)
	for _, syscallsToBlock := range syscallsToBlock {
		syscallsWithNoArgsToBlock[syscallsToBlock] = []specs.LinuxSeccompArg{}
	}

	p.BlockSyscallsWithArgs(syscallsWithNoArgsToBlock)
}
