package apparmor

import (
	"io"
	"github.com/moby/moby/pkg/templates"
	"os"
	"path"
)

var (
	// profileDirectory is the file store for apparmor profiles and macros.
	profileDirectory = "/etc/apparmor.d"
)

type networkRawSetup struct {
	Denied bool
}

/* See http://manpages.ubuntu.com/manpages/precise/man5/apparmor.d.5.html
 * for more information regarding supported protocols, network data types
 * and domains.
 */
type NetworkSetup struct {
	/* AllowedProtocols can be one of the following:
	 * 'tcp', 'udp', 'icmp'
	 */
	AllowedProtocols []string
	Raw networkRawSetup
}

type CapabilitiesSetup struct {
	/* Currently supported capabilities are:
	 * "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap",
     * "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
     * "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
     * "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap",
     * "mac_override", "mac_admin"
	 */
	Allowed []string
	Denied []string
}

type FilesSetup struct {
	// Denied is a list of filepaths to deny any access to
	Denied []string
	// ReadOnly is a list of filepaths to restrict to read access only
	ReadOnly []string
	// NoExec is a list of filepaths for which execution is denied
	NoExec []string
}

// profileData holds information about the given profile for generation.
type ProfileData struct {
	// Name is profile name.
	Name string
	// Imports defines the apparmor functions to import, before defining the profile.
	Imports []string
	// InnerImports defines the apparmor functions to import in the profile.
	InnerImports []string
	// Version is the {major, minor, patch} version of apparmor_parser as a single number.
	Version int

	// Network defines the network setup we want, see NetworkSetup type definition
	Network NetworkSetup

	// Capabilities defines the capabilities setup we want, see CapabiltitiesSetup type definition
	Capabilities CapabilitiesSetup

	// Files defines the files access setup we want, see FilesSetup type definition
	Files FilesSetup
}

func NewProfileData(name string) *ProfileData {
	return &ProfileData{Name: name}
}

// macrosExists checks if the passed macro exists.
func macroExists(m string) bool {
	_, err := os.Stat(path.Join(profileDirectory, m))
	return err == nil
}

func generateAppArmorProfile(p ProfileData, out io.Writer) error {
	aaProfile, err := templates.NewParse("apparmor_profile", baseCustomTemplate)
	if err != nil {
		return err
	}

	if macroExists("tunables/global") {
		p.Imports = append(p.Imports, "#include <tunables/global>")
	} else {
		p.Imports = append(p.Imports, "@{PROC}=/proc/")
	}

	if macroExists("abstractions/base") {
		p.InnerImports = append(p.InnerImports, "#include <abstractions/base>")
	}

	// FIXME: add `aaparser` pkg
	/*
	ver, err := aaparser.GetVersion()
	if err != nil {
		return err
	}
	*/

	return aaProfile.Execute(out, p)
}