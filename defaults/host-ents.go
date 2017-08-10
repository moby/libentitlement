package defaults

import (
	"github.com/docker/libentitlement/entitlement"
	"github.com/docker/libentitlement/secprofile"
	"github.com/docker/libentitlement/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"reflect"
)

const (
	hostDomain = "host"

	hostProcessesDomain = hostDomain + ".processes"
	hostDevicesDomain   = hostDomain + ".devices"
)

const (
	// HostDevicesNoneEntFullID is the ID for the host.devices.none entitlement
	HostDevicesNoneEntFullID = hostDevicesDomain + ".none"
	// HostDevicesViewEntFullID is the ID for the host.devices.view entitlement
	HostDevicesViewEntFullID = hostDevicesDomain + ".view"
	// HostDevicesAdminEntFullID is the ID for the host.devices.admin entitlement
	HostDevicesAdminEntFullID = hostDevicesDomain + ".admin"

	// HostProcessesNoneEntFullID is the ID for the host.processes.none entitlement
	HostProcessesNoneEntFullID = hostProcessesDomain + ".none"
	// HostProcessesAdminEntFullID is the ID for the host.processes.admin entitlement
	HostProcessesAdminEntFullID = hostProcessesDomain + ".admin"
)

var (
	hostDevicesNoneEntitlement  = entitlement.NewVoidEntitlement(HostDevicesNoneEntFullID, hostDevicesNoneEntitlementEnforce)
	hostDevicesViewEntitlement  = entitlement.NewVoidEntitlement(HostDevicesViewEntFullID, hostDevicesViewEntitlementEnforce)
	hostDevicesAdminEntitlement = entitlement.NewVoidEntitlement(HostDevicesAdminEntFullID, hostDevicesAdminEntitlementEnforce)

	hostProcessesNoneEntitlement  = entitlement.NewVoidEntitlement(HostProcessesNoneEntFullID, hostProcessesNoneEntitlementEnforce)
	hostProcessesAdminEntitlement = entitlement.NewVoidEntitlement(HostProcessesAdminEntFullID, hostProcessesAdminEntitlementEnforce)
)

var (
	allowedMounts = []specs.Mount{
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

func removeReadOnlyFlagMount(mount specs.Mount) specs.Mount {
	readWriteMount := mount
	for index, option := range readWriteMount.Options {
		if option == "ro" {
			readWriteMount.Options = append(readWriteMount.Options[:index], readWriteMount.Options[index+1:]...)
			break
		}
	}

	return readWriteMount
}

func removeReadOnlyFlagMounts(mounts []specs.Mount) []specs.Mount {
	readWriteMounts := make([]specs.Mount, len(mounts))

	for mountIndex, mount := range mounts {
		readWriteMounts[mountIndex] = removeReadOnlyFlagMount(mount)
	}

	return readWriteMounts
}

func hostDevicesAdminEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostDevicesAdminEntFullID)
	if err != nil {
		return nil, err
	}

	ociProfile.OCI.Mounts = removeReadOnlyFlagMounts(allowedMounts)

	ociProfile.OCI.Linux.MaskedPaths = []string{}

	capsToAdd := []types.Capability{
		CapSysAdmin,
	}
	ociProfile.AddCaps(capsToAdd...)

	return ociProfile, nil
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
