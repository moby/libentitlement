package defaults

import (
	"fmt"
	"github.com/docker/libentitlement/entitlement"
	secProfile "github.com/docker/libentitlement/security-profile"
	"github.com/opencontainers/runtime-spec/specs-go"
	"syscall"
)

const (
	networkDomain = "network"
)

const (
	NetworkNoneEntFullId  = networkDomain + ".none"
	NetworkUserEntFullId  = networkDomain + ".user"
	NetworkProxyEntFullId = networkDomain + ".proxy"
	NetworkAdminEntFullId = networkDomain + ".admin"
)

var (
	networkNoneEntitlement  = entitlement.NewVoidEntitlement(NetworkNoneEntFullId, networkNoneEntitlementEnforce)
	networkUserEntitlement  = entitlement.NewVoidEntitlement(NetworkUserEntFullId, networkUserEntitlementEnforce)
	networkProxyEntitlement = entitlement.NewVoidEntitlement(NetworkProxyEntFullId, networkProxyEntitlementEnforce)
	networkAdminEntitlement = entitlement.NewVoidEntitlement(NetworkAdminEntFullId, networkAdminEntitlementEnforce)
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
func networkNoneEntitlementEnforce(profile secProfile.Profile) (secProfile.Profile, error) {
	if profile.GetType() != secProfile.OciProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", NetworkNoneEntFullId)
	}

	ociProfile, ok := profile.(*secProfile.OciProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", NetworkNoneEntFullId)
	}

	capsToRemove := []string{"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_NET_BROADCAST"}
	ociProfile.RemoveCaps(capsToRemove...)

	pathsToMask := []string{"/proc/pid/net", "/proc/sys/net", "/sys/class/net"}
	ociProfile.AddMaskedPaths(pathsToMask...)

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	ociProfile.AddNamespaces(nsToAdd...)

	syscallsToBlock := []string{"socket", "socketpair", "setsockopt", "getsockopt", "getsockname", "getpeername",
		"bind", "listen", "accept", "accept4", "connect", "shutdown", "recvfrom", "recvmsg", "sendto",
		"sendmsg", "sendmmsg", "sethostname", "setdomainname",
	}
	ociProfile.BlockSyscalls(syscallsToBlock...)

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
	ociProfile.AllowSyscallsWithArgs(syscallsWithArgsToAllow)

	// FIXME: build an Apparmor Profile if necessary + add `deny network`

	return profile, nil
}

/* Implements "network.user" entitlement
 * - No caps: CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE
 * - Authorized caps: CAP_NET_BROADCAST
 * - Blocked syscalls:
 * 	sethostname, setdomainname, setsockopt(SO_DEBUG)
 */
func networkUserEntitlementEnforce(profile secProfile.Profile) (secProfile.Profile, error) {
	if profile.GetType() != secProfile.OciProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", NetworkUserEntFullId)
	}

	ociProfile, ok := profile.(*secProfile.OciProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", NetworkUserEntFullId)
	}

	capsToRemove := []string{"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW"}
	ociProfile.RemoveCaps(capsToRemove...)

	capsToAdd := []string{"CAP_NET_BROADCAST"}
	ociProfile.AddCaps(capsToAdd...)

	syscallsToBlock := []string{
		"sethostname", "setdomainname", "setsockopt",
	}
	ociProfile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToAllow := map[string][]specs.LinuxSeccompArg{
		"setsockopt": {
			{
				Index: 2,
				Value: syscall.SO_DEBUG,
				Op:    specs.OpNotEqual,
			},
		},
	}
	ociProfile.AllowSyscallsWithArgs(syscallsWithArgsToAllow)

	return profile, nil
}

/* Implements "network.proxy" entitlement
 * - No caps: CAP_NET_ADMIN
 * - Authorized caps: CAP_NET_BROADCAST, CAP_NET_RAW, CAP_NET_BIND_SERVICE
 * - Blocked syscalls:
 * 	setsockopt(SO_DEBUG)
 */
func networkProxyEntitlementEnforce(profile secProfile.Profile) (secProfile.Profile, error) {
	if profile.GetType() != secProfile.OciProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", NetworkProxyEntFullId)
	}

	ociProfile, ok := profile.(*secProfile.OciProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", NetworkProxyEntFullId)
	}

	capsToRemove := []string{"CAP_NET_ADMIN"}
	ociProfile.RemoveCaps(capsToRemove...)

	capsToAdd := []string{"CAP_NET_BROADCAST", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE"}
	ociProfile.AddCaps(capsToAdd...)

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
	ociProfile.BlockSyscallsWithArgs(syscallsWithArgsToBlock)

	return profile, nil
}

/* Implements "network.admin" entitlement
 * - Authorized caps: CAP_NET_ADMIN, CAP_NET_BROADCAST, CAP_NET_RAW, CAP_NET_BIND_SERVICE
 */
func networkAdminEntitlementEnforce(profile secProfile.Profile) (secProfile.Profile, error) {
	if profile.GetType() != secProfile.OciProfileType {
		return nil, fmt.Errorf("%s not implemented for non-OCI profiles", NetworkAdminEntFullId)
	}

	ociProfile, ok := profile.(*secProfile.OciProfile)
	if !ok {
		return nil, fmt.Errorf("%s: error converting to OCI profile", NetworkAdminEntFullId)
	}

	capsToAdd := []string{"CAP_NET_BROADCAST", "CAP_NET_RAW", "CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN"}
	ociProfile.AddCaps(capsToAdd...)

	return profile, nil
}
