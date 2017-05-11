package defaults

import (
	secProfile "github.com/docker/libentitlement/security-profile"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func removeCapFromList(capList []string, capToRemove string) []string {
	for index, cap  := range capList {
		if cap == capToRemove {
			return append(capList[:index], capList[index+1])
		}
	}

	return capList
}

func removeCaps(profile *secProfile.Profile, capsToRemove ...string) []string {
	for _, cap := range capsToRemove {
		profile.Process.Capabilities.Bounding = removeCapFromList(profile.Process.Capabilities.Bounding, cap)
		profile.Process.Capabilities.Effective = removeCapFromList(profile.Process.Capabilities.Effective, cap)
		profile.Process.Capabilities.Inheritable = removeCapFromList(profile.Process.Capabilities.Inheritable, cap)
		profile.Process.Capabilities.Permitted = removeCapFromList(profile.Process.Capabilities.Permitted, cap)
		profile.Process.Capabilities.Ambient = removeCapFromList(profile.Process.Capabilities.Ambient, cap)
	}
}

func addMaskedPaths(profile *secProfile.Profile, pathsToMask ...string) {
	for _, dir := range pathsToMask {
		exists := false
		for _, paths := range profile.Linux.MaskedPaths {
			if paths == dir {
				exists = true
				break
			}
		}

		if !exists {
			profile.Linux.MaskedPaths = append(profile.Linux.MaskedPaths, dir)
		}
	}
}

func addNamespaces(profile *secProfile.Profile, nsTypes ...specs.LinuxNamespaceType) {
	for _, ns := range nsTypes {
		exists := false
		for _, namespace := range profile.Linux.Namespaces {
			if namespace.Type == ns {
				exists = true
				break
			}
		}

		if !exists {
			newNs := specs.LinuxNamespace{Type: ns}
			profile.Linux.Namespaces = append(profile.Linux.Namespaces, newNs)
		}
	}
}

func blockSyscalls(profile *secProfile.Profile, syscallsToBlock ...string) {
	/* For each syscall to block we browse each syscall list of each Seccomp rule */
	for _, syscallToBlock := range syscallsToBlock {
		blocked := false

		for syscallRuleIndex, syscallRule := range profile.Linux.Seccomp.Syscalls {

			switch syscallRule.Action {
			case specs.ActAllow, specs.ActTrace, specs.ActTrap:
				for syscallNameIndex, syscallName := range syscallRule.Names {
					/* We found the syscall in the syscall list in a rule */
					if syscallName == syscallToBlock {
						/* If this is the only one, just remove that rule from the Seccomp config */
						if len(profile.Linux.Seccomp.Syscalls[syscallRuleIndex].Names) == 1 {
							profile.Linux.Seccomp.Syscalls = append(
								profile.Linux.Seccomp.Syscalls[0:syscallRuleIndex],
								profile.Linux.Seccomp.Syscalls[syscallRuleIndex+1:]...
							)

							break
						}

						/* Otherwise, remove it from the rule */
						profile.Linux.Seccomp.Syscalls[syscallRuleIndex].Names = append(
							profile.Linux.Seccomp.Syscalls[syscallRuleIndex].Names[0:syscallNameIndex],
							profile.Linux.Seccomp.Syscalls[syscallRuleIndex].Names[syscallNameIndex+1:]...
						)
					}
				}

			case specs.ActErrno, specs.ActKill:
				for _, syscallName := range syscallRule.Names {
					/* We found the syscall in the syscall list in a rule */
					if syscallName == syscallToBlock {
						blocked = true

						/* We'll keep looking in next rules outside of this loop as
						 * SECCOMP_RET_TRAP has precedence over SECCOMP_RET_ERRNO for example
						 * and we want to make sure we remove all those occurences
						 */
						break
					}
				}
			}
		}

		/* If we havn't found it in a blocking rule, we add one that simply returns dummy Errno */
		if !blocked {
			newRule := specs.LinuxSyscall{
				Names: []string{syscallToBlock},
				Action: specs.ActErrno,
				Args: []specs.LinuxSeccompArg{},
			}
			profile.Linux.Seccomp.Syscalls = append(profile.Linux.Seccomp.Syscalls, newRule)
		}

	}
}