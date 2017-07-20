package defaults

import (
	"github.com/docker/libentitlement/entitlement"
	"github.com/docker/libentitlement/secprofile"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/docker/libentitlement/types"
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

	ociProfile.OCI.Mounts = []specs.Mount{}

	return ociProfile, nil
}

// FIXME: Not implemented yet
func hostDevicesViewEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostDevicesViewEntFullID)
	if err != nil {
		return nil, err
	}

	for _, mount := range ociProfile.OCI.Mounts {
		mountPath := mount.Destination
		ociProfile.OCI.Linux.ReadonlyPaths = append(ociProfile.OCI.Linux.ReadonlyPaths, mountPath)
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