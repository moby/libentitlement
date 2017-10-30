package defaults

import (
	"reflect"

	"github.com/moby/libentitlement/entitlement"
	"github.com/moby/libentitlement/secprofile"
	"github.com/moby/libentitlement/secprofile/osdefs"
	"github.com/moby/libentitlement/types"
	"github.com/opencontainers/runtime-spec/specs-go"
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

func isAllowedMount(mount specs.Mount) bool {
	for _, allowedMount := range osdefs.DefaultMobyAllowedMounts {
		if reflect.DeepEqual(mount, allowedMount) {
			return true
		}
	}

	return false
}

/* Implements "host.devices.none" entitlement
 * - Blocked Capabilities: CAP_SYS_ADMIN
 * - Sets all files in sysfs as read-only
 * - Prevents access to files under /proc/kcore
 * - Sets allowed mounts with associated mount options to Moby defaults
 */
func hostDevicesNoneEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostDevicesNoneEntFullID)
	if err != nil {
		return nil, err
	}

	capsToRemove := []types.Capability{
		osdefs.CapSysAdmin,
	}
	ociProfile.RemoveCaps(capsToRemove...)

	ociProfile.AppArmorSetup.Files.ReadOnly = append(ociProfile.AppArmorSetup.Files.ReadOnly, "/sys/**")
	ociProfile.AppArmorSetup.Files.Denied = append(ociProfile.AppArmorSetup.Files.Denied, "/proc/kcore/**")

	ociProfile.OCI.Linux.ReadonlyPaths = append(ociProfile.OCI.Linux.ReadonlyPaths, "/sys")
	ociProfile.OCI.Linux.MaskedPaths = append(ociProfile.OCI.Linux.MaskedPaths, "/proc/kcore")

	ociProfile.OCI.Mounts = osdefs.DefaultMobyAllowedMounts

	return ociProfile, nil
}

/* Implements "host.devices.view" entitlement
 * - Sets all custom mount destinations to read-only
 */
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

// removeReadOnlyFlagMounts removes the read-only "ro" flag from a mount object's mount options
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

// removeReadOnlyFlagMounts removes the read-only "ro" flag from mount options of a provided list of mounts
func removeReadOnlyFlagMounts(mounts []specs.Mount) []specs.Mount {
	readWriteMounts := make([]specs.Mount, len(mounts))

	for mountIndex, mount := range mounts {
		readWriteMounts[mountIndex] = removeReadOnlyFlagMount(mount)
	}

	return readWriteMounts
}

/* Implements "host.devices.admin" entitlement
 * - Allowed Capabilities: CAP_SYS_ADMIN
 * - Sets mounts as Read-Write
 * - No paths masked to the container
 */
func hostDevicesAdminEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostDevicesAdminEntFullID)
	if err != nil {
		return nil, err
	}

	// FIXME: just remove read-only flags for default mounts and leave additional mounts as is
	ociProfile.OCI.Mounts = removeReadOnlyFlagMounts(ociProfile.OCI.Mounts)

	ociProfile.OCI.Linux.MaskedPaths = []string{}

	capsToAdd := []types.Capability{
		osdefs.CapSysAdmin,
	}
	ociProfile.AddCaps(capsToAdd...)

	return ociProfile, nil
}

/* Implements "host.processes.none" entitlement
 * - Activates PID Namespace
 */
func hostProcessesNoneEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostProcessesNoneEntFullID)
	if err != nil {
		return nil, err
	}

	nsToAdd := []specs.LinuxNamespaceType{
		specs.PIDNamespace,
	}
	ociProfile.AddNamespaces(nsToAdd...)

	return ociProfile, nil
}

/* Implements "host.processes.admin" entitlement
 * - Deactivates PID Namespace
 */
func hostProcessesAdminEntitlementEnforce(profile secprofile.Profile) (secprofile.Profile, error) {
	ociProfile, err := ociProfileConversionCheck(profile, HostProcessesAdminEntFullID)
	if err != nil {
		return nil, err
	}

	nsToRemove := []specs.LinuxNamespaceType{
		specs.PIDNamespace,
	}
	ociProfile.RemoveNamespaces(nsToRemove...)

	return ociProfile, nil
}
