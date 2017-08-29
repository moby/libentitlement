package defaults

import (
	"encoding/json"
	"fmt"
	"github.com/opencontainers/runtime-spec/specs-go"
	"io/ioutil"
)

func setDefaultSeccompProfile() (*specs.LinuxSeccomp, error) {
	var profile specs.LinuxSeccomp

	jsonProfile, err := ioutil.ReadFile("seccomp_default.json")
	if err != nil {
		return nil, fmt.Errorf("Reading default seccomp profile failed: %v", err)
	}

	err = json.Unmarshal(jsonProfile, &profile)
	if err != nil {
		return nil, fmt.Errorf("Decoding default seccomp profile failed: %v", err)
	}

	return &profile, nil
}
