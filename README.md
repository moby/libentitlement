# libentitlement

`libentitlement` is currently WIP for a proof-of-concept that implements this
proposal: https://github.com/moby/moby/issues/32801 but would also handle on the
long term a broader scope of constraints on different containers management 
platforms.

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
  - a security context with `context.Context` type (for now it's an OCI specs struct)
  - an entitlement parameter if the entitlement needs one (other than `VoidEntitlement`)
