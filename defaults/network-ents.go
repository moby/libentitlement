package defaults

import (
	secProfile "github.com/docker/libentitlement/security-profile"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var NetworkTLD = "network"

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