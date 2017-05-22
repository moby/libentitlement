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
	NetworkNoneEntId  = "none"  // network.none
	NetworkUserEntId  = "user"  // network.user
	NetworkProxyEntId = "proxy" // network.proxy
	NetworkAdminEntId = "admin" // network.admin
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
	profile.RemoveCaps(capsToRemove...)

	pathsToMask := []string{"/proc/pid/net", "/proc/sys/net", "/sys/class/net"}
	profile.AddMaskedPaths(pathsToMask...)

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	profile.AddNamespaces(nsToAdd...)

	syscallsToBlock := []string{"socket", "socketpair", "setsockopt", "getsockopt", "getsockname", "getpeername",
		"bind", "listen", "accept", "accept4", "connect", "shutdown", "recvfrom", "recvmsg", "sendto",
		"sendmsg", "sendmmsg", "sethostname",
	}
	profile.BlockSyscalls(syscallsToBlock...)

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
	profile.RemoveCaps(capsToRemove...)

	capsToAdd := []string{"CAP_NET_BROADCAST"}
	profile.AddCaps(capsToAdd...)

	syscallsToBlock := []string{
		"sethostname", "setdomainname", "bpf",
	}
	profile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToBlock := map[string][]specs.LinuxSeccompArg{
		"setsockopt": {
			{
				Index:    2,
				Value:    syscall.SO_DEBUG,
				ValueTwo: 0,
				Op:       specs.OpEqualTo,
			},
		},
	}
	profile.BlockSyscallsWithArgs(syscallsWithArgsToBlock)

	return profile, nil
}

func NetworkProxyEntitlement(profile *secProfile.Profile) (*secProfile.Profile, error) {
	capsToRemove := []string{"CAP_NET_ADMIN"}
	profile.RemoveCaps(capsToRemove...)

	capsToAdd := []string{"CAP_NET_BROADCAST", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE"}
	profile.AddCaps(capsToAdd...)

	syscallsWithArgsToBlock := map[string][]specs.LinuxSeccompArg{
		"setsockopt": {
			{
				Index:    2,
				Value:    syscall.SO_DEBUG,
				ValueTwo: 0,
				Op:       specs.OpEqualTo,
			},
		},
	}
	profile.BlockSyscallsWithArgs(syscallsWithArgsToBlock)

	return profile, nil
}

func NetworkAdminEntitlement(profile *secProfile.Profile) (*secProfile.Profile, error) {
	capsToAdd := []string{"CAP_NET_BROADCAST", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN"}
	profile.AddCaps(capsToAdd...)
  
	return profile, nil
}
