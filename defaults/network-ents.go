package defaults

import (
	"syscall"

	"github.com/docker/libentitlement/entitlement"
	"github.com/docker/libentitlement/secprofile"
	"github.com/docker/libentitlement/types"
	"github.com/opencontainers/runtime-spec/specs-go"
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
func networkNoneEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, NetworkNoneEntFullID)
	if err != nil {
		return nil, err
	}

	capsToRemove := []types.Capability{CapNetAdmin, CapNetBindService, CapNetRaw, CapNetBroadcast}
	ociProfile.RemoveCaps(capsToRemove...)

	pathsToMask := []string{"/proc/pid/net", "/proc/sys/net", "/sys/class/net"}
	ociProfile.AddMaskedPaths(pathsToMask...)

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	ociProfile.AddNamespaces(nsToAdd...)

	syscallsToBlock := []types.Syscall{SysSocket, SysSocketpair, SysSetsockopt, SysGetsockopt, SysGetsockname, SysGetpeername,
		SysBind, SysListen, SysAccept, SysAccept4, SysConnect, SysShutdown, SysRecvfrom, SysRecvmsg, SysRecvmmsg, SysSendto,
		SysSendmsg, SysSendmmsg, SysSethostname, SysSetdomainname,
	}
	ociProfile.BlockSyscalls(syscallsToBlock...)

	syscallsWithArgsToAllow := map[types.Syscall][]specs.LinuxSeccompArg{
		SysSocket: {
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
func networkUserEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, NetworkUserEntFullID)
	if err != nil {
		return nil, err
	}

	capsToRemove := []types.Capability{CapNetAdmin, CapNetBindService, CapNetRaw}
	ociProfile.RemoveCaps(capsToRemove...)

	//syscallsToBlock := []types.Syscall{
	//	SysSethostname, SysSetdomainname, SysSetsockopt,
	//}
	//ociProfile.BlockSyscalls(syscallsToBlock...)
	//
	//syscallsWithArgsToAllow := map[types.Syscall][]specs.LinuxSeccompArg{
	//	SysSetsockopt: {
	//		{
	//			Index: 2,
	//			Value: syscall.SO_DEBUG,
	//			Op:    specs.OpNotEqual,
	//		},
	//	},
	//}
	//ociProfile.AllowSyscallsWithArgs(syscallsWithArgsToAllow)

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	ociProfile.AddNamespaces(nsToAdd...)

	return profile, nil
}

/* Implements "network.proxy" entitlement
 * - No caps: CAP_NET_ADMIN
 * - Authorized caps: CAP_NET_BROADCAST, CAP_NET_RAW, CAP_NET_BIND_SERVICE
 * - Blocked syscalls:
 * 	setsockopt(SO_DEBUG)
 */
func networkProxyEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, NetworkProxyEntFullID)
	if err != nil {
		return nil, err
	}

	capsToRemove := []types.Capability{CapNetAdmin}
	ociProfile.RemoveCaps(capsToRemove...)

	capsToAdd := []types.Capability{CapNetRaw, CapNetBindService}
	ociProfile.AddCaps(capsToAdd...)

	syscallsWithArgsToBlock := map[types.Syscall][]specs.LinuxSeccompArg{
		SysSetsockopt: {
			{
				Index:    2,
				Value:    syscall.SO_DEBUG,
				ValueTwo: 0,
				Op:       specs.OpEqualTo,
			},
		},
	}
	ociProfile.BlockSyscallsWithArgs(syscallsWithArgsToBlock)

	nsToAdd := []specs.LinuxNamespaceType{specs.NetworkNamespace}
	ociProfile.AddNamespaces(nsToAdd...)

	return profile, nil
}

/* Implements "network.admin" entitlement
 * - Authorized caps: CAP_NET_ADMIN, CAP_NET_BROADCAST, CAP_NET_RAW, CAP_NET_BIND_SERVICE
 */
func networkAdminEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, NetworkAdminEntFullID)
	if err != nil {
		return nil, err
	}

	capsToAdd := []types.Capability{CapNetAdmin, CapNetRaw, CapNetBindService, CapNetBroadcast}
	ociProfile.AddCaps(capsToAdd...)

	return profile, nil
}
