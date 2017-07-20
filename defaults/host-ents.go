package defaults

import (
	"github.com/docker/libentitlement/entitlement"
	"github.com/docker/libentitlement/secprofile"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/docker/libentitlement/types"
	"reflect"
)

const (
	hostDomain = "host"

	hostProcessesDomain = hostDomain + ".process"
	hostDevicesDomain = hostDomain + ".device"
)

const (
	HostDevicesNoneEntFullID = hostDevicesDomain + ".none"
	HostDevicesViewEntFullID = hostDevicesDomain + ".view"
	HostDevicesAdminEntFullID = hostDevicesDomain + ".admin"

	HostProcessesNoneEntFullID = hostProcessesDomain + ".none"
	HostProcessesViewEntFullID = hostProcessesDomain + ".view"
	HostProcessesAdminEntFullID = hostProcessesDomain + ".admin"
)

var (
	hostDevicesNoneEntitlement = entitlement.NewVoidEntitlement(HostDevicesNoneEntFullID, hostDevicesNoneEntitlementEnforce)
	hostDevicesViewEntitlement = entitlement.NewVoidEntitlement(HostDevicesViewEntFullID, hostDevicesViewEntitlementEnforce)
	hostDevicesAdminEntitlement = entitlement.NewVoidEntitlement(HostDevicesAdminEntFullID, hostDevicesAdminEntitlementEnforce)

	hostProcessesNoneEntitlement = entitlement.NewVoidEntitlement(HostProcessesNoneEntFullID, hostProcessesNoneEntitlementEnforce)
	hostProcessesAdminEntitlement = entitlement.NewVoidEntitlement(HostProcessesAdminEntFullID, hostProcessesAdminEntitlementEnforce)
)

var (
	allowedMounts = []specs.Mount {
		{
			Destination: "/proc",
			Type:        "proc",
			Source:      "proc",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
		{
			Destination: "/dev",
			Type:        "tmpfs",
			Source:      "tmpfs",
			Options:     []string{"nosuid", "strictatime", "mode=755"},
		},
		{
			Destination: "/dev/pts",
			Type:        "devpts",
			Source:      "devpts",
			Options:     []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"},
		},
		{
			Destination: "/sys",
			Type:        "sysfs",
			Source:      "sysfs",
			Options:     []string{"nosuid", "noexec", "nodev", "ro"},
		},
		{
			Destination: "/sys/fs/cgroup",
			Type:        "cgroup",
			Source:      "cgroup",
			Options:     []string{"ro", "nosuid", "noexec", "nodev"},
		},
		{
			Destination: "/dev/mqueue",
			Type:        "mqueue",
			Source:      "mqueue",
			Options:     []string{"nosuid", "noexec", "nodev"},
		},
	}
)

func isAllowedMount(mount specs.Mount) bool {
	for _, allowedMount := range allowedMounts {
		if reflect.DeepEqual(mount, allowedMount) {
			return true
		}
	}

	return false
}

func hostDevicesNoneEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostDevicesNoneEntFullID)
	if err != nil {
		return nil, err
	}

	capsToRemove := []types.Capability{
		CapSysAdmin,
	}
	ociProfile.RemoveCaps(capsToRemove...)

	ociProfile.AppArmorSetup.Files.ReadOnly = append(ociProfile.AppArmorSetup.Files.ReadOnly, "/sys/**")
	ociProfile.AppArmorSetup.Files.Denied = append(ociProfile.AppArmorSetup.Files.Denied, "/proc/kcore/**")

	ociProfile.OCI.Linux.ReadonlyPaths = append(ociProfile.OCI.Linux.ReadonlyPaths, "/sys")
	ociProfile.OCI.Linux.MaskedPaths = append(ociProfile.OCI.Linux.MaskedPaths, "/proc/kcore")

	ociProfile.OCI.Mounts = allowedMounts

	return ociProfile, nil
}

func hostDevicesViewEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostDevicesViewEntFullID)
	if err != nil {
		return nil, err
	}

	for _, mount := range ociProfile.OCI.Mounts {
		mountPath := mount.Destination

		if !isAllowedMount(mount) {
			ociProfile.OCI.Linux.ReadonlyPaths = append(ociProfile.OCI.Linux.ReadonlyPaths, mountPath)
		}
	}

	return ociProfile, nil
}

func hostDevicesAdminEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostDevicesAdminEntFullID)
	if err != nil {
		return nil, err
	}

	capsToAdd := []types.Capability{
		CapSysAdmin,
	}
	ociProfile.AddCaps(capsToAdd...)
}

func hostProcessesNoneEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostProcessesNoneEntFullID)
	if err != nil {
		return nil, err
	}

	nsToAdd := []specs.LinuxNamespaceType{
		specs.UserNamespace,
	}
	ociProfile.AddNamespaces(nsToAdd...)

	return ociProfile, nil
}

func hostProcessesAdminEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostProcessesAdminEntFullID)
	if err != nil {
		return nil, err
	}

	nsToRemove := []specs.LinuxNamespaceType{
		specs.UserNamespace,
	}
	ociProfile.RemoveNamespaces(nsToRemove...)

	return ociProfile, nil
}