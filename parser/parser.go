package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// FIXME: refactor shared code between each Parse[..]Entitlement functions
// FIXME: create error objects

// isAlphanumOrDash is a regex matching alphanum string containing alphanum substrings separated by single dashes
var isAlphanumOrDash = regexp.MustCompile(`^[a-zA-Z0-9]+(\-[a-zA-Z0-9]+)*$`).MatchString

// IsValidDomainName returns whether a given string is a valid domain name
func IsValidDomainName(domain string) bool {
	return isAlphanumOrDash(domain)
}

// IsValidDomainNameList returns whether the list of domain names contains all valid domain names
func IsValidDomainNameList(domain []string) bool {
	for _, domainField := range domain {
		if IsValidDomainName(domainField) == false {
			return false
		}
	}

	return true
}

// IsValidIdentifier returns whether the given string is a valid identifier
func IsValidIdentifier(identifier string) bool {
	return isAlphanumOrDash(identifier)
}

// ParseVoidEntitlement parses an entitlement with the following format: "domain-name.identifier"
func ParseVoidEntitlement(entitlementFormat string) (domain []string, id string, err error) {
	stringList := strings.Split(entitlementFormat, ".")
	if len(stringList) < 2 {
		return nil, "", fmt.Errorf("Parsing of entitlement %s failed: either domain or id missing", entitlementFormat)
	}

	id = stringList[len(stringList)-1]
	domain = stringList[0 : len(stringList)-1]

	if IsValidDomainNameList(domain) == false {
		return nil, "", fmt.Errorf("Parsing of entitlement %s failed: domain must be alphanumeric and can contain '-'. '.' is a domain separator", entitlementFormat)
	}

	if IsValidIdentifier(id) == false {
		return nil, "", fmt.Errorf("Parsing of entitlement %s failed: identifier must be alphanumeric and can contain '-'", entitlementFormat)
	}

	return
}

// ParseIntEntitlement parses an entitlement with the following format: "domain-name.identifier=int64-value"
func ParseIntEntitlement(entitlementFormat string) (domain []string, id string, value int, err error) {
	stringList := strings.Split(entitlementFormat, ".")
	if len(stringList) < 2 {
		return nil, "", 0, fmt.Errorf("Parsing of int entitlement %s failed: either domain or id missing", entitlementFormat)
	}

	idAndArgString := stringList[len(stringList)-1]
	domain = stringList[0 : len(stringList)-2]

	if IsValidDomainNameList(domain) == false {
		return nil, "", 0, fmt.Errorf("Parsing of int entitlement %s failed: domain must be alphanumeric and can contain '-'. '.' is a domain separator", entitlementFormat)
	}

	idAndArgList := strings.Split(idAndArgString, "=")
	if len(idAndArgList) != 2 {
		return nil, "", 0, fmt.Errorf("Parsing of int entitlement %s failed: format required 'domain-name.identifier=int-value'", entitlementFormat)
	}

	id = idAndArgList[0]
	valueString := idAndArgList[1]

	if IsValidIdentifier(id) == false {
		return nil, "", 0, fmt.Errorf("Parsing of int entitlement %s failed: identifier must be alphanumeric and can contain '-'", entitlementFormat)
	}

	value, err = strconv.Atoi(valueString)
	if err != nil {
		return nil, "", 0, fmt.Errorf("Parsing of int entitlement %s failed: entitlement argument must be a 64bits integer", entitlementFormat)
	}

	return
}

// ParseStringEntitlement parses an entitlement with the following format: "domain-name.identifier=string-value"
func ParseStringEntitlement(entitlementFormat string) (domain []string, id, value string, err error) {
	stringList := strings.Split(entitlementFormat, ".")
	if len(stringList) < 2 {
		return nil, "", "", fmt.Errorf("Parsing of string entitlement %s failed: either domain or id missing", entitlementFormat)
	}

	idAndArgString := stringList[len(stringList)-1]
	domain = stringList[0 : len(stringList)-2]

	if IsValidDomainNameList(domain) == false {
		return nil, "", "", fmt.Errorf("Parsing of string entitlement %s failed: domain must be alphanumeric and can contain '-'. '.' is a domain separator", entitlementFormat)
	}

	idAndArgList := strings.Split(idAndArgString, "=")
	if len(idAndArgList) != 2 {
		return nil, "", "", fmt.Errorf("Parsing of string entitlement %s failed: format required 'domain-name.identifier=param'", entitlementFormat)
	}

	id = idAndArgList[0]
	value = idAndArgList[1]

	if IsValidIdentifier(id) == false {
		return nil, "", "", fmt.Errorf("Parsing of string entitlement %s failed: identifier must be alphanumeric and can contain '-'", entitlementFormat)
	}

	// FIXME: should we add constraints on the allowed characters in entitlement parameters and check integrity?

	return
}
