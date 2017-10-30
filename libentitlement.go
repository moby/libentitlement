package libentitlement

import (
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"

	"github.com/moby/libentitlement/defaults"
	"github.com/moby/libentitlement/domain"
	"github.com/moby/libentitlement/entitlement"
	secprofile "github.com/moby/libentitlement/secprofile"
)

// EntitlementsManager generates enforceable profiles from its entitlements and domains state
type EntitlementsManager struct {
	profile         secprofile.Profile
	entitlementList []entitlement.Entitlement
	domainManager   *domainmanager.DomainManager
}

// NewEntitlementsManager instantiates an EntitlementsManager object with the given profile
// default
func NewEntitlementsManager(profile secprofile.Profile) *EntitlementsManager {
	if profile == nil {
		logrus.Errorf("Entilements Manager initialization: invalid security profile - cannot be nil")
		return nil
	}

	return &EntitlementsManager{
		profile:         profile,
		entitlementList: make([]entitlement.Entitlement, 0),
		domainManager:   domainmanager.NewDomainManager(),
	}
}

// GetProfile returns the current state of the security profile
func (m *EntitlementsManager) GetProfile() (secprofile.Profile, error) {
	if m.profile == nil {
		return nil, fmt.Errorf("Entitlements Manager doesn't have a security profile")
	}

	return m.profile, nil
}

// SetProfile sets the entitlement manager's security profile
func (m *EntitlementsManager) SetProfile(profile secprofile.Profile) error {
	if profile == nil {
		return fmt.Errorf("Invalid security profile")
	}

	m.profile = profile
	return nil
}

func isValidEntitlement(ent entitlement.Entitlement) (bool, error) {
	_, err := ent.Identifier()
	if err != nil {
		return false, err
	}

	_, err = ent.Domain()
	if err != nil {
		return false, err
	}

	_, err = ent.Value()
	if err != nil {
		return false, err
	}

	return true, nil
}

// AddDefault adds a default entitlement identified by entName which must be a default identifier.
func (m *EntitlementsManager) AddDefault(entName string) error {
	defaultEnt, ok := defaults.DefaultEntitlements[entName]
	if !ok {
		return fmt.Errorf("Couldn't add invalid default entitlement name: %s", entName)
	}

	return m.Add(defaultEnt)
}

// Add adds the given entitlements to the current entitlements list, updates the domain name system and enforce
// the entitlement on the security profile
func (m *EntitlementsManager) Add(entitlements ...entitlement.Entitlement) error {
	if m.profile == nil {
		return fmt.Errorf("Couldn't add to invalid security profile")
	}

	for _, ent := range entitlements {
		if isValid, err := isValidEntitlement(ent); isValid == false {
			return fmt.Errorf("Couldn't add invalid entitlement: %v", err)
		}

		profile, err := ent.Enforce(m.profile)
		if err != nil {
			return err
		}

		identifier, _ := ent.Identifier()
		domainString, _ := ent.Domain()
		domainList := strings.Split(domainString, ".")

		err = m.domainManager.AddFullDomainWithEntitlementID(domainList, identifier)
		if err != nil {
			// Should not happen since we verified isValidEntitlement
			// FIXME: we should probably revert the changes on the security profile
			return err
		}

		m.profile = profile

		m.entitlementList = append(m.entitlementList, ent)
	}

	return nil
}

func isEqual(ent1, ent2 entitlement.Entitlement) (bool, error) {
	id1, err := ent1.Identifier()
	if err != nil {
		return false, err
	}

	dom1, err := ent1.Domain()
	if err != nil {
		return false, err
	}

	val1, err := ent1.Value()
	if err != nil {
		return false, err
	}

	id2, err := ent2.Identifier()
	if err != nil {
		return false, err
	}

	dom2, err := ent2.Domain()
	if err != nil {
		return false, err
	}

	val2, err := ent2.Value()
	if err != nil {
		return false, err
	}

	return id1 == id2 && dom1 == dom2 && val1 == val2, nil
}

// HasEntitlement returns whether the given entitlement is registered in the current entitlements list
func (m *EntitlementsManager) HasEntitlement(ent entitlement.Entitlement) (bool, error) {
	if isValid, err := isValidEntitlement(ent); isValid == false {
		return false, fmt.Errorf("Couldn't check  invalid entitlement: %v", err)
	}

	for _, currEnt := range m.entitlementList {
		// Only compare entitlements id, domain and value
		entEqual, err := isEqual(currEnt, ent)
		if err != nil {
			return false, err
		}

		if entEqual == true {
			return true, nil
		}
	}

	return false, nil
}

// Enforce applies the constraints on the security profile and updates it to be used for the container
func (m *EntitlementsManager) Enforce() error {
	for _, ent := range m.entitlementList {
		if isValid, err := isValidEntitlement(ent); isValid == false {
			return fmt.Errorf("Couldn't enforce invalid entitlement: %v", err)
		}

		// Try to enforce the entitlement on the security profile
		profile, err := m.GetProfile()
		if err != nil {
			return err
		}

		newProfile, err := ent.Enforce(profile)
		if err != nil {
			return err
		}

		m.profile = newProfile
	}

	return nil
}
