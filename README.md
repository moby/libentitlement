# libentitlement

`libentitlement` is currently WIP for a proof-of-concept that implements this
proposal: https://github.com/moby/moby/issues/32801 but would also handle on the
long term a broader scope of constraints on different containers management 
platforms.

### Design

`libentitlement` is designed to be a library to manage containers
security profiles. It provides a way to register specific grants that add or
remove constraints on those profiles.

A platform using `libentitlement` should initialize a set of entitlements with
the following types:
- `VoidEntitlement`: entitlements without parameters
- `IntEntitlement`: entitlements with an int parameter
- `StringEntitlement`: entitlements with a string parameter

Entitlements can be initialize with two parameters:
- `fullName`: a string with the following format `domain-name.identifier[=argument]`
- `callback`: a entitlement enforcement callback that takes the following arguments:
  - a security profile with `security-profile.Profile` type (for now it's an OCI specs struct)
  - an entitlement parameter if the entitlement needs one (other than `VoidEntitlement`)

## Example
A quick example on how to use entitlements in your container manager:
```golang
/* 'context.Profile' type is an OCI specs config struct for now
 * We'll add abstract API access management in it. This is the security
 * profile to modify in your entitlement.
 * You should provide your own initialized profile to the entitlement manager.
 */
ctx := context.NewProfile()

/* Initialize an entitlement manager which manages entitlements and provide them with
 * an updated security profile
 */
entMgr := NewEntitlementsManager(ctx)

/* This is where you implement your entitlements.
 * We can  for example initialize a void entitlement callback which adds the "CAP_SYS_ADMIN"
 * capability to a security profile.
 */
capSysAdminEntCallback := func (ctx *secProfile.Profile) (*secProfile.Profile, error) {
	if ctx == nil {
		return nil, fmt.Errorf("CapSysAdminVoidEntCallback - profile is nil.")
	}
	capToAdd := "CAP_SYS_ADMIN"

	if ctx.Process == nil {
		ctx.Process = &specs.Process{}
	}

	if ctx.Process.Capabilities == nil {
		caps := []string{capToAdd}
		ctx.Process.Capabilities = &specs.LinuxCapabilities{
			Bounding: caps,
			Effective: caps,
			Permitted: caps,
			Inheritable: caps,
			Ambient: []string{},
		}
	} else {
		ctx.Process.Capabilities.Bounding = append(ctx.Process.Capabilities.Bounding, capToAdd)
		ctx.Process.Capabilities.Effective = append(ctx.Process.Capabilities.Effective, capToAdd)
		ctx.Process.Capabilities.Permitted = append(ctx.Process.Capabilities.Permitted, capToAdd)
		ctx.Process.Capabilities.Inheritable = append(ctx.Process.Capabilities.Inheritable, capToAdd)
	}

	return ctx, nil
}

/* We can call our entitlement "cap-sys-admin" and have it under the "security.custom.caps" domain
 * Note: "security.custom.caps.cap-sys-admin" is different from "foobar.cap-sys-admin" as they are
 * in two different domains.
 */
capSysAdminEntFullName := "security.custom.cap-sys-admin"

/* We create a void entitlement (no parameter) with the name and the callback */
capSysAdminVoidEnt := entitlement.NewVoidEntitlement(capSysAdminEntFullName, capSysAdminEntCallback)

/* Ask the entitlement manager to add it, entitlements are enforced when added */
err := entMgr.Add(capSysAdminVoidEnt)
```

This is as simple as that.

## Copyright and license

Code and documentation copyright 2017 Docker, inc. - All rights reserved.