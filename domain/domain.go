package domainmanager

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/docker/libentitlement/parser"
	"strings"
)

type Domain struct {
	name           string
	subdomains     map[string]*Domain
	entitlementIds map[string]bool
}

func NewDomain(name string) *Domain {
	if parser.IsValidDomainName(name) == false {
		logrus.Errorf("Invalid domain name for: %s", name)
	}

	subdomainsMap := make(map[string]*Domain)
	entitlementIdList := make(map[string]bool)

	return &Domain{name: name, subdomains: subdomainsMap, entitlementIds: entitlementIdList}
}

func (d *Domain) AddSubdomains(subdomains ...*Domain) {
	for _, subdomain := range subdomains {
		d.subdomains[subdomain.name] = subdomain
	}
}

func (d *Domain) AddEntitlementIds(entitlementIds ...string) {
	for _, entitlementId := range entitlementIds {
		if _, ok := d.entitlementIds[entitlementId]; !ok {
			d.entitlementIds[entitlementId] = true
		}
	}
}

type DomainManager struct {
	domains map[string]*Domain
}

func NewDomainManager() *DomainManager {
	return &DomainManager{domains: make(map[string]*Domain)}
}

// Add a complete subdomain "chain" to a TLD
func addFullSubdomainWithEntitlementIdtoTLD(tld *Domain, fullSubdomain []string, entitlementId string) {
	// Shouldn't happen, so do nothing
	if len(fullSubdomain) < 1 || tld == nil {
		return
	}

	currentLevelDomainName := fullSubdomain[0]

	// We are treating the last domain component of the list so we add the entitlement ID to it
	if len(fullSubdomain) == 1 {
		currentLevelDomain := NewDomain(currentLevelDomainName)
		currentLevelDomain.AddEntitlementIds(entitlementId)

		if _, ok := tld.subdomains[currentLevelDomainName]; !ok {
			tld.subdomains[currentLevelDomainName] = currentLevelDomain
		}

		return
	}

	nextLevels := fullSubdomain[1:]

	currentLevelDomain := NewDomain(currentLevelDomainName)

	addFullSubdomainWithEntitlementIdtoTLD(currentLevelDomain, nextLevels, entitlementId)

	if _, ok := tld.subdomains[currentLevelDomainName]; !ok {
		tld.subdomains[currentLevelDomainName] = currentLevelDomain
	}
}

func (m *DomainManager) AddFullDomainWithEntitlementId(fulldomain []string, entitlementId string) error {
	if len(fulldomain) == 0 {
		return fmt.Errorf("Invalid domain - can't add entitlementId: %s", entitlementId)
	}

	if parser.IsValidDomainNameList(fulldomain) == false {
		return fmt.Errorf("Invalid domain name: %s", strings.Join(fulldomain, "."))
	}

	tldName := fulldomain[0]

	if len(fulldomain) == 1 {
		if _, ok := m.domains[tldName]; !ok {
			m.domains[tldName] = NewDomain(tldName)
		}

		if _, ok := m.domains[tldName].entitlementIds[entitlementId]; !ok {
			m.domains[tldName].entitlementIds[entitlementId] = true
		}

		return nil
	}

	fullSubdomain := fulldomain[1:]

	if _, ok := m.domains[tldName]; !ok {
		m.domains[tldName] = NewDomain(tldName)
	}

	addFullSubdomainWithEntitlementIdtoTLD(m.domains[tldName], fullSubdomain, entitlementId)

	return nil
}
