package types

import (
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
)

const maxAuthorizationDataDepth = 8

// ErrAuthorizationDataDepth indicates excessive AD-IF-RELEVANT nesting.
var ErrAuthorizationDataDepth = errors.New("authorization-data nesting exceeds limit")

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.6

// AuthorizationData implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6
type AuthorizationData []AuthorizationDataEntry

// AuthorizationDataEntry implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6
type AuthorizationDataEntry struct {
	ADType int32  `asn1:"explicit,tag:0"`
	ADData []byte `asn1:"explicit,tag:1"`
}

// ADIfRelevant implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6.1
type ADIfRelevant AuthorizationData

// ADKDCIssued implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6.2
type ADKDCIssued struct {
	ADChecksum Checksum          `asn1:"explicit,tag:0"`
	IRealm     string            `asn1:"optional,generalstring,explicit,tag:1"`
	Isname     PrincipalName     `asn1:"optional,explicit,tag:2"`
	Elements   AuthorizationData `asn1:"explicit,tag:3"`
}

// ADAndOr implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6.3
type ADAndOr struct {
	ConditionCount int32             `asn1:"explicit,tag:0"`
	Elements       AuthorizationData `asn1:"explicit,tag:1"`
}

// ADMandatoryForKDC implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.6.4
type ADMandatoryForKDC AuthorizationData

// Unmarshal bytes into the ADKDCIssued.
func (a *ADKDCIssued) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, a)
}

// Unmarshal bytes into the AuthorizationData.
func (a *AuthorizationData) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, a)
}

// Unmarshal bytes into the AuthorizationDataEntry.
func (a *AuthorizationDataEntry) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, a)
}

// Walk visits every authorization-data entry and recursively expands
// AD-IF-RELEVANT containers. Top-level entries have depth zero.
func (a AuthorizationData) Walk(fn func(depth int, entry AuthorizationDataEntry) error) error {
	return a.walk(0, fn)
}

// EntriesOfType returns all authorization-data entries with the requested
// type, including entries nested in AD-IF-RELEVANT containers.
func (a AuthorizationData) EntriesOfType(adType int32) ([]AuthorizationDataEntry, error) {
	var matches []AuthorizationDataEntry
	err := a.Walk(func(_ int, entry AuthorizationDataEntry) error {
		if entry.ADType == adType {
			matches = append(matches, entry)
		}
		return nil
	})
	return matches, err
}

func (a AuthorizationData) walk(depth int, fn func(int, AuthorizationDataEntry) error) error {
	for _, entry := range a {
		if err := fn(depth, entry); err != nil {
			return err
		}
		if entry.ADType != adtype.ADIfRelevant {
			continue
		}
		nested, err := decodeADIfRelevant(entry.ADData, depth)
		if err != nil {
			return err
		}
		if err := nested.walk(depth+1, fn); err != nil {
			return err
		}
	}
	return nil
}

func decodeADIfRelevant(data []byte, depth int) (AuthorizationData, error) {
	if depth >= maxAuthorizationDataDepth {
		return nil, fmt.Errorf("%w: depth %d", ErrAuthorizationDataDepth, depth+1)
	}
	var nested AuthorizationData
	rest, err := asn1.Unmarshal(data, &nested)
	if err != nil {
		return nil, fmt.Errorf("decode AD-IF-RELEVANT at depth %d: %w", depth, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("decode AD-IF-RELEVANT at depth %d: %d trailing bytes", depth, len(rest))
	}
	return nested, nil
}
