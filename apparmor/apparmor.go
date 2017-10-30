package apparmor

import (
	"io"
	"os"
	"path"

	"github.com/moby/libentitlement/templates"
)

const (
	// defaultProfileDirectory is the apparmor default profile's directory
	defaultProfileDirectory = "/etc/apparmor.d"
)

var (
	// profileDirectory is the file store for apparmor profiles and macros.
	profileDirectory = defaultProfileDirectory
)

type networkRawSetup struct {
	Denied bool
}

/*
NetworkSetup contains flags and data to configure network rules in AppArmor.
See http://manpages.ubuntu.com/manpages/precise/man5/apparmor.d.5.html
for more information regarding supported protocols, network data types
and domains.
*/
type NetworkSetup struct {
	Denied           bool
	AllowedProtocols []string
	Raw              networkRawSetup
}

/*
CapabilitiesSetup contains flags and data to configure capability rules in AppArmor.
See http://manpages.ubuntu.com/manpages/precise/man5/apparmor.d.5.html
for more information regarding supported capabilities.
*/
type CapabilitiesSetup struct {
	Allowed []string
	Denied  []string
}

// FilesSetup contains data to configure filesystem access rules in AppArmor.
type FilesSetup struct {
	// Denied is a list of filepaths to deny any access to
	Denied []string
	// ReadOnly is a list of filepaths to restrict to read access only
	ReadOnly []string
	// NoExec is a list of filepaths for which execution is denied
	NoExec []string
}

// ProfileData holds information about the given profile for generation.
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

// NewEmptyProfileData creates an empty ProfileData object with its name.
func NewEmptyProfileData(name string) *ProfileData {
	return &ProfileData{Name: name}
}

// macrosExists checks if the passed macro exists.
func macroExists(m string) bool {
	_, err := os.Stat(path.Join(profileDirectory, m))
	return err == nil
}

// SetAppArmorProfileDirectory sets AppArmor's profile directory
func SetAppArmorProfileDirectory(path string) {
	profileDirectory = path
}

// GenerateAppArmorProfile creates an AppArmor profile and writes it to the io.Writer argument
func GenerateAppArmorProfile(p ProfileData, out io.Writer) error {
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
