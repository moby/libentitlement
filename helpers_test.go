package libentitlement

import (
	"github.com/opencontainers/runtime-spec/specs-go"
)

func testSpec() *specs.Spec {
	s := &specs.Spec{
		Process: specs.Process{
			Capabilities: &specs.LinuxCapabilities{
				Bounding:    []string{},
				Effective:   []string{},
				Inheritable: []string{},
				Permitted:   []string{},
				Ambient:     []string{},
			},
		},
		Linux: &specs.Linux{
			Seccomp:   &specs.LinuxSeccomp{},
			Resources: &specs.LinuxResources{},
			IntelRdt:  &specs.LinuxIntelRdt{},
		},
		Windows: &specs.Windows{
			Resources: &specs.WindowsResources{
				Memory:  &specs.WindowsMemoryResources{},
				CPU:     &specs.WindowsCPUResources{},
				Storage: &specs.WindowsStorageResources{},
				Network: &specs.WindowsNetworkResources{},
			},
		},
	}

	return s
}
