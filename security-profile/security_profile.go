package security_profile

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"reflect"
)

type AppArmorProfile struct {
	Rules []string
}

// Profile maintains some OCI spec settings but should also contain a complete security
// context.
// Profiles should be maintained for both Linux and Windows at any given time.
// FIXME: Add error handling here if profile or subfields are not allocated */
// Fixme add api access settings for Engine / Swarm / K8s?
type Profile struct {
	Oci      *specs.Spec
	AppArmor *AppArmorProfile
}

func NewProfile(ociSpec *specs.Spec) *Profile {
	return &Profile{Oci: ociSpec}
}

/* Add a list of capabilities if not present to all capability masks */
func (p *Profile) AddCaps(capsToAdd ...string) {
	for _, cap := range capsToAdd {
		p.Oci.Process.Capabilities.Bounding = addCapToList(p.Oci.Process.Capabilities.Bounding, cap)
		p.Oci.Process.Capabilities.Effective = addCapToList(p.Oci.Process.Capabilities.Effective, cap)
		p.Oci.Process.Capabilities.Inheritable = addCapToList(p.Oci.Process.Capabilities.Inheritable, cap)
		p.Oci.Process.Capabilities.Permitted = addCapToList(p.Oci.Process.Capabilities.Permitted, cap)

		// Should be updated automatically if the previous masks are set
		p.Oci.Process.Capabilities.Ambient = addCapToList(p.Oci.Process.Capabilities.Ambient, cap)
	}
}

/* Remove a list of capabilities if present from all capability masks */
func (p *Profile) RemoveCaps(capsToRemove ...string) {
	for _, cap := range capsToRemove {
		p.Oci.Process.Capabilities.Bounding = removeCapFromList(p.Oci.Process.Capabilities.Bounding, cap)
		p.Oci.Process.Capabilities.Effective = removeCapFromList(p.Oci.Process.Capabilities.Effective, cap)
		p.Oci.Process.Capabilities.Inheritable = removeCapFromList(p.Oci.Process.Capabilities.Inheritable, cap)
		p.Oci.Process.Capabilities.Permitted = removeCapFromList(p.Oci.Process.Capabilities.Permitted, cap)

		// Should be updated automatically if the previous masks are set
		p.Oci.Process.Capabilities.Ambient = removeCapFromList(p.Oci.Process.Capabilities.Ambient, cap)
	}
}

/* Add a list of paths to the set of paths masked in the container if not present yet */
func (p *Profile) AddMaskedPaths(pathsToMask ...string) {
	for _, dir := range pathsToMask {
		exists := false
		for _, paths := range p.Oci.Linux.MaskedPaths {
			if paths == dir {
				exists = true
				break
			}
		}

		if !exists {
			p.Oci.Linux.MaskedPaths = append(p.Oci.Linux.MaskedPaths, dir)
		}
	}
}

/* Add a list of namespaces to the enabled namespaces */
func (p *Profile) AddNamespaces(nsTypes ...specs.LinuxNamespaceType) {
	for _, ns := range nsTypes {
		exists := false
		for _, namespace := range p.Oci.Linux.Namespaces {
			if namespace.Type == ns {
				exists = true
				break
			}
		}

		if !exists {
			newNs := specs.LinuxNamespace{Type: ns}
			p.Oci.Linux.Namespaces = append(p.Oci.Linux.Namespaces, newNs)
		}
	}
}

/* Add seccomp rules to block syscalls with the given arguments and remove them from allowed/debug rules if present */
func (p *Profile) BlockSyscallsWithArgs(syscallsWithArgsToBlock map[string][]specs.LinuxSeccompArg) {
	/* For each syscall to block we browse each syscall list of each Seccomp rule */
	for syscallNameToBlock, syscallArgsToBlock := range syscallsWithArgsToBlock {
		blocked := false

		for syscallRuleIndex, syscallRule := range p.Oci.Linux.Seccomp.Syscalls {

			switch syscallRule.Action {
			case specs.ActAllow, specs.ActTrace, specs.ActTrap:
				for syscallNameIndex, syscallName := range syscallRule.Names {
					/* We found the syscall in the syscall list in a rule and arguments are identical */
					if syscallName == syscallNameToBlock &&
						reflect.DeepEqual(syscallRule.Args, syscallArgsToBlock) {

						/* If this is the only one, just remove that rule from the Seccomp config */
						if len(p.Oci.Linux.Seccomp.Syscalls[syscallRuleIndex].Names) == 1 {
							p.Oci.Linux.Seccomp.Syscalls = append(
								p.Oci.Linux.Seccomp.Syscalls[0:syscallRuleIndex],
								p.Oci.Linux.Seccomp.Syscalls[syscallRuleIndex+1:]...,
							)

							break
						}

						/* Otherwise, remove it from the rule */
						p.Oci.Linux.Seccomp.Syscalls[syscallRuleIndex].Names = append(
							p.Oci.Linux.Seccomp.Syscalls[syscallRuleIndex].Names[0:syscallNameIndex],
							p.Oci.Linux.Seccomp.Syscalls[syscallRuleIndex].Names[syscallNameIndex+1:]...,
						)
					}
				}

			case specs.ActErrno, specs.ActKill:
				for _, syscallName := range syscallRule.Names {
					/* We found the syscall in the syscall list in a rule */
					if syscallName == syscallNameToBlock {
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
		if !blocked {
			newRule := specs.LinuxSyscall{
				Names:  []string{syscallNameToBlock},
				Action: specs.ActErrno,
				Args:   syscallArgsToBlock,
			}
			p.Oci.Linux.Seccomp.Syscalls = append(p.Oci.Linux.Seccomp.Syscalls, newRule)
		}

	}
}

/* Block a list of syscalls without specific arguments */
func (p *Profile) BlockSyscalls(syscallsToBlock ...string) {
	syscallsWithNoArgsToBlock := make(map[string][]specs.LinuxSeccompArg)
	for _, syscallsToBlock := range syscallsToBlock {
		syscallsWithNoArgsToBlock[syscallsToBlock] = []specs.LinuxSeccompArg{}
	}

	p.BlockSyscallsWithArgs(syscallsWithNoArgsToBlock)
}
