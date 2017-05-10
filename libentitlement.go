package libentitlement

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/docker/libentitlement/context"
	"github.com/docker/libentitlement/entitlement"
)

type EntitlementsManager struct {
	context         *context.Context
	entitlementList []entitlement.Entitlement
}

// NewEntitlementsManager() instantiates an EntitlementsManager object with the given context
// default
func NewEntitlementsManager(ctx *context.Context) *EntitlementsManager {
	if ctx == nil {
		logrus.Errorf("EntilementsManager initialization: invalid security context - cannot be nil")
		return nil
	}

	return &EntitlementsManager{context: ctx, entitlementList: make([]entitlement.Entitlement, 0)}
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

// Add() adds the given entitlements to the current entitlements list and enforce them
func (m *EntitlementsManager) Add(entitlements ...entitlement.Entitlement) error {
	if m.context == nil {
		return fmt.Errorf("Couldn't add to invalid security context")
	}

	for _, ent := range entitlements {
		if isValid, err := isValidEntitlement(ent); isValid == false {
			return fmt.Errorf("Couldn't add invalid entitlement: %v", err)
		}

		ctx, err := ent.Enforce(m.context)
		if err != nil {
			return err
		}

		m.context = ctx

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

// HasEntitlement() returns wether the given entitlement is registered in the current entitlements list
func (m *EntitlementsManager) HasEntitlement(ent entitlement.Entitlement) (bool, error) {
	if isValid, err := isValidEntitlement(ent); isValid == false {
		return false, fmt.Errorf("Couldn't validate invalid entitlement: %v", err)
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

// Enforce() applies the constraints on the security context and updates it to be used for the container
func (m *EntitlementsManager) Enforce() error {
	for _, ent := range m.entitlementList {
		if isValid, err := isValidEntitlement(ent); isValid == false {
			return fmt.Errorf("Couldn't enforce invalid entitlement: %v", err)
		}

		// Try to enforce the entitlement on the security context
		newContext, err := ent.Enforce(m.GetContext())
		if err != nil {
			return err
		}

		m.context = newContext
	}

	return nil
}

// GetContext() returns the current state of the security context
func (m *EntitlementsManager) GetContext() *context.Context {
	return m.context
}
