package security_profile

/* Profile is an abstract interface which represents security profiles.
 * Each security profile has its own type and its own API as needs
 * may vary across different profile formats.
 */
type Profile interface {
	GetType() string
}
