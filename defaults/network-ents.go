package defaults

import (
	"syscall"

	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/docker/libentitlement/entitlement"
	secprofile "github.com/docker/libentitlement/secprofile"
)

const (
	networkDomain = "network"
)

const (
	// NetworkNoneEntFullID is the ID for the network.none entitlement
	NetworkNoneEntFullID = networkDomain + ".none"
	// NetworkUserEntFullID is the ID for the network.user entitlement
	NetworkUserEntFullID = networkDomain + ".user"
	// NetworkProxyEntFullID is the ID for the network.proxy entitlement
	NetworkProxyEntFullID = networkDomain + ".proxy"
	// NetworkAdminEntFullID is the ID for the network.admin entitlement
	NetworkAdminEntFullID = networkDomain + ".admin"
)

var (
	networkNoneEntitlement  = entitlement.NewVoidEntitlement(NetworkNoneEntFullID, networkNoneEntitlementEnforce)
	networkUserEntitlement  = entitlement.NewVoidEntitlement(NetworkUserEntFullID, networkUserEntitlementEnforce)
	networkProxyEntitlement = entitlement.NewVoidEntitlement(NetworkProxyEntFullID, networkProxyEntitlementEnforce)
	networkAdminEntitlement = entitlement.NewVoidEntitlement(NetworkAdminEntFullID, networkAdminEntitlementEnforce)
)

/* Implements "network.none" entitlement
 * - No access to /proc/pid/net, /proc/sys/net, /sys/class/net
 * - No caps: CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_NET_BROADCAST
 * - Blocked syscalls:
 *     socket, socketpair, setsockopt, getsockopt, getsockname, getpeername, bind, listen, accept,
 *     accept4, connect, shutdown,recvfrom, recvmsg, sendto, sendmsg, sendmmsg, sethostname,
 *     setdomainname, socket for non AF_LOCAL/AF_UNIX domain
 * - Add network namespace
 */
func networkNoneEntitlementEnforce(profile *secprofile.Profile) (*secprofile.Profile, error) {
	capsToRemove := []string{"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_NET_BROADCAST"}
	profile.RemoveCaps(capsToRemove...)

	pathsToMask := []string{"/proc/pid/net", "/proc/sys/net", "/sys/class/net"}
	profile.AddMaskedPaths(pathsToMask...)

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	profile.AddNamespaces(nsToAdd...)

	syscallsToBlock := []string{"socket", "socketpair", "setsockopt", "getsockopt", "getsockname", "getpeername",
		"bind", "listen", "accept", "accept4", "connect", "shutdown", "recvfrom", "recvmsg", "sendto",
		"sendmsg", "sendmmsg", "sethostname", "setdomainname",
	}
	profile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToAllow := map[string][]specs.LinuxSeccompArg{
		"socket": {
			{
				Index: 0,
				Op:    specs.OpEqualTo,
				Value: syscall.AF_UNIX,
			},
			{
				Index: 0,
				Op:    specs.OpEqualTo,
				Value: syscall.AF_LOCAL,
			},
		},
	}
	profile.AllowSyscallsWithArgs(syscallsWithArgsToAllow)

	// FIXME: build an Apparmor Profile if necessary + add `deny network`

	return profile, nil
}

/* Implements "network.user" entitlement
 * - No caps: CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE
 * - Authorized caps: CAP_NET_BROADCAST
 * - Blocked syscalls:
 * 	sethostname, setdomainname, setsockopt(SO_DEBUG)
 */
func networkUserEntitlementEnforce(profile *secprofile.Profile) (*secprofile.Profile, error) {
	capsToRemove := []string{"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW"}
	profile.RemoveCaps(capsToRemove...)

	capsToAdd := []string{"CAP_NET_BROADCAST"}
	profile.AddCaps(capsToAdd...)

	syscallsToBlock := []string{
		"sethostname", "setdomainname", "setsockopt",
	}
	profile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToAllow := map[string][]specs.LinuxSeccompArg{
		"setsockopt": {
			{
				Index: 2,
				Value: syscall.SO_DEBUG,
				Op:    specs.OpNotEqual,
			},
		},
	}
	profile.AllowSyscallsWithArgs(syscallsWithArgsToAllow)

	return profile, nil
}

/* Implements "network.proxy" entitlement
 * - No caps: CAP_NET_ADMIN
 * - Authorized caps: CAP_NET_BROADCAST, CAP_NET_RAW, CAP_NET_BIND_SERVICE
 * - Blocked syscalls:
 * 	setsockopt(SO_DEBUG)
 */
func networkProxyEntitlementEnforce(profile *secprofile.Profile) (*secprofile.Profile, error) {
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

/* Implements "network.admin" entitlement
 * - Authorized caps: CAP_NET_ADMIN, CAP_NET_BROADCAST, CAP_NET_RAW, CAP_NET_BIND_SERVICE
 */
func networkAdminEntitlementEnforce(profile *secprofile.Profile) (*secprofile.Profile, error) {
	capsToAdd := []string{"CAP_NET_BROADCAST", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN"}
	profile.AddCaps(capsToAdd...)

	return profile, nil
}
