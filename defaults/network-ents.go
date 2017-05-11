package defaults

import (
	secProfile "github.com/docker/libentitlement/security-profile"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var NetworkTLD = "network"

func removeCapFromCapList(capList []string, capToRemove string) []string {
	for index, cap  := range capList {
		if cap == capToRemove {
			return append(capList[:index], capList[index+1])
		}
	}

	return capList
}

func

/* No access to /proc/pid/net, /proc/sys/net, /sys/class/net
 * No caps: NET_ADMIN, NET_BIND_SERVICE, NET_RAW
 * Blocked syscalls:
 *     socket, socketpair, setsockopt, getsockopt, getsockname, getpeername, bind, listen, accept,
 *     accept4, connect, shutdown,recvfrom, recvmsg, sendto, sendmsg, sendmmsg, sethostname,
 *     setdomainname, bpf
 * Add network namespace
 */
func NetworkNoneEntitlement(profile *secProfile.Profile) (*secProfile.Profile, error) {
	capsToRemove := []string{"CAP_NET_ADMIN", "NET_BIND_SERVICE", "CAP_NET_RAW"}
	for _, cap := range capsToRemove {
		profile.Process.Capabilities.Bounding = removeCapFromCapList(profile.Process.Capabilities.Bounding, cap)
		profile.Process.Capabilities.Effective = removeCapFromCapList(profile.Process.Capabilities.Effective, cap)
		profile.Process.Capabilities.Inheritable = removeCapFromCapList(profile.Process.Capabilities.Inheritable, cap)
		profile.Process.Capabilities.Permitted = removeCapFromCapList(profile.Process.Capabilities.Permitted, cap)
		profile.Process.Capabilities.Ambient = removeCapFromCapList(profile.Process.Capabilities.Ambient, cap)
	}

	fsDirToBlockRWX := []string{"/proc/pid/net", "/proc/sys/net", "/sys/class/net"}
	for _, dir := range fsDirToBlockRWX {
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

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	for _, ns := range nsToAdd {
		exists := false
		for _, namespace := range profile.Linux.Namespaces {
			if namespace.Type == ns {
				exists = true
				break
			}
		}

		if !exists {
			newNs := specs.LinuxNamespace{Type:ns}
			profile.Linux.Namespaces = append(profile.Linux.Namespaces, newNs)
		}
	}

	syscallsToBlock :=

	return profile, nil
}