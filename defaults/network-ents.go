package defaults

import (
	secProfile "github.com/docker/libentitlement/security-profile"
	"github.com/opencontainers/runtime-spec/specs-go"
	"syscall"
)

const (
	NetworkTLD = "network"
)

const (
	NetworkNoneEntId = "none"	// network.none
	NetworkUserEntId = "user"	// network.user
	NetworkProxyEntId = "proxy"	// network.proxy
	NetworkAdminEntId = "admin"	// network.admin
)

/* Implements "network.none" entitlement
 * - No access to /proc/pid/net, /proc/sys/net, /sys/class/net
 * - No caps: CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_NET_BROADCAST
 * - Blocked syscalls:
 *     socket, socketpair, setsockopt, getsockopt, getsockname, getpeername, bind, listen, accept,
 *     accept4, connect, shutdown,recvfrom, recvmsg, sendto, sendmsg, sendmmsg, sethostname,
 *     setdomainname, bpf
 * - Add network namespace
 */
func NetworkNoneEntitlement(profile *secProfile.Profile) (*secProfile.Profile, error) {
	capsToRemove := []string{"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_NET_BROADCAST"}
	removeCaps(profile, capsToRemove...)


	pathsToMask := []string{"/proc/pid/net", "/proc/sys/net", "/sys/class/net"}
	addMaskedPaths(profile, pathsToMask...)

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	addNamespaces(profile, nsToAdd...)

	syscallsToBlock := []string{"socket", "socketpair", "setsockopt", "getsockopt", "getsockname", "getpeername",
		"bind", "listen", "accept", "accept4", "connect", "shutdown", "recvfrom", "recvmsg", "sendto",
		"sendmsg", "sendmmsg", "sethostname",
	}
	blockSyscalls(profile, syscallsToBlock...)

	return profile, nil
}

/* Implements "network.user" entitlement
 * - No caps: CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE
 * - Authorized caps: CAP_NET_BROADCAST
 * - Blocked syscalls:
 * 	sethostname, setdomainname bpf, setsockopt(SO_DEBUG)
 */
func NetworkUserEntitlement(profile *secProfile.Profile) (*secProfile.Profile, error) {
	capsToRemove := []string{"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW"}
	removeCaps(profile, capsToRemove...)

	capsToAdd := []string{"CAP_NET_BROADCAST"}
	addCaps(profile, capsToAdd...)

	syscallsToBlock := []string{
		"sethostname", "setdomainname", "bpf",
	}
	blockSyscalls(profile, syscallsToBlock...)

	syscallsWithArgsToBlock := map[string][]specs.LinuxSeccompArg{
		"setsockopt": []specs.LinuxSeccompArg{
			specs.LinuxSeccompArg{
				Index: 2,
				Value: syscall.SO_DEBUG,
				ValueTwo: 0,
				Op: specs.OpEqualTo,
			},
		},
	}
	blockSyscallsWithArgs(profile, syscallsWithArgsToBlock)
}