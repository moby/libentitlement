package domainmanager

import (
	"fmt"
	"strings"

	"github.com/moby/libentitlement/parser"

	"github.com/sirupsen/logrus"
)

// Domain defines the scoping for entitlements, ie Network
type Domain struct {
	name           string
	subdomains     map[string]*Domain
	entitlementIDs map[string]bool
}

// NewDomain instantiates a new domain according the provided string name
func NewDomain(name string) *Domain {
	if parser.IsValidDomainName(name) == false {
		logrus.Errorf("Invalid domain name for: %s", name)
	}

	subdomainsMap := make(map[string]*Domain)
	entitlementIDList := make(map[string]bool)

	return &Domain{name: name, subdomains: subdomainsMap, entitlementIDs: entitlementIDList}
}

// AddSubdomains adds subdomains to the given domain
func (d *Domain) AddSubdomains(subdomains ...*Domain) {
	for _, subdomain := range subdomains {
		d.subdomains[subdomain.name] = subdomain
	}
}

// AddEntitlementIDs adds entitlements by IDs to the given domain
func (d *Domain) AddEntitlementIDs(entitlementIDs ...string) {
	for _, entitlementID := range entitlementIDs {
		if _, ok := d.entitlementIDs[entitlementID]; !ok {
			d.entitlementIDs[entitlementID] = true
		}
	}
}

// DomainManager keeps a map of domains by name
type DomainManager struct {
	domains map[string]*Domain
}

// NewDomainManager instantiates an empty Domainmanager
func NewDomainManager() *DomainManager {
	return &DomainManager{domains: make(map[string]*Domain)}
}

// Add a complete subdomain "chain" to a TLD
func addFullSubdomainWithEntitlementIDtoTLD(tld *Domain, fullSubdomain []string, entitlementID string) {
	// Shouldn't happen, so do nothing
	if len(fullSubdomain) < 1 || tld == nil {
		return
	}

	currentLevelDomainName := fullSubdomain[0]

	// We are treating the last domain component of the list so we add the entitlement ID to it
	if len(fullSubdomain) == 1 {
		currentLevelDomain := NewDomain(currentLevelDomainName)
		currentLevelDomain.AddEntitlementIDs(entitlementID)

		if _, ok := tld.subdomains[currentLevelDomainName]; !ok {
			tld.subdomains[currentLevelDomainName] = currentLevelDomain
		}

		return
	}

	nextLevels := fullSubdomain[1:]

	currentLevelDomain := NewDomain(currentLevelDomainName)

	addFullSubdomainWithEntitlementIDtoTLD(currentLevelDomain, nextLevels, entitlementID)

	if _, ok := tld.subdomains[currentLevelDomainName]; !ok {
		tld.subdomains[currentLevelDomainName] = currentLevelDomain
	}
}

// AddFullDomainWithEntitlementID adds entitlements by IDs to a list of domains
func (m *DomainManager) AddFullDomainWithEntitlementID(fulldomain []string, entitlementID string) error {
	if len(fulldomain) == 0 {
		return fmt.Errorf("Invalid domain - can't add entitlementID: %s", entitlementID)
	}

	if parser.IsValidDomainNameList(fulldomain) == false {
		return fmt.Errorf("Invalid domain name: %s", strings.Join(fulldomain, "."))
	}

	tldName := fulldomain[0]

	if len(fulldomain) == 1 {
		if _, ok := m.domains[tldName]; !ok {
			m.domains[tldName] = NewDomain(tldName)
		}

		if _, ok := m.domains[tldName].entitlementIDs[entitlementID]; !ok {
			m.domains[tldName].entitlementIDs[entitlementID] = true
		}

		return nil
	}

	fullSubdomain := fulldomain[1:]

	if _, ok := m.domains[tldName]; !ok {
		m.domains[tldName] = NewDomain(tldName)
	}

	addFullSubdomainWithEntitlementIDtoTLD(m.domains[tldName], fullSubdomain, entitlementID)

	return nil
}
