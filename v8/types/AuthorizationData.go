package types

import (
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/adtype"
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
	_, err := asn1.Unmarshal(b, a)
	return err
}

// Unmarshal bytes into the AuthorizationData.
func (a *AuthorizationData) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

// Unmarshal bytes into the AuthorizationDataEntry.
func (a *AuthorizationDataEntry) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

// Walk visits every authorization-data entry and recursively expands
// AD-IF-RELEVANT containers. Top-level entries have depth zero.
func (a AuthorizationData) Walk(fn func(depth int, entry AuthorizationDataEntry) error) error {
	var walk func(AuthorizationData, int) error
	walk = func(entries AuthorizationData, depth int) error {
		for _, entry := range entries {
			if err := fn(depth, entry); err != nil {
				return err
			}
			if entry.ADType != adtype.ADIfRelevant {
				continue
			}
			if depth >= maxAuthorizationDataDepth {
				return fmt.Errorf("%w: depth %d", ErrAuthorizationDataDepth, depth+1)
			}
			var nested AuthorizationData
			rest, err := asn1.Unmarshal(entry.ADData, &nested)
			if err != nil {
				return fmt.Errorf("decode AD-IF-RELEVANT at depth %d: %w", depth, err)
			}
			if len(rest) != 0 {
				return fmt.Errorf("decode AD-IF-RELEVANT at depth %d: %d trailing bytes", depth, len(rest))
			}
			if err := walk(nested, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(a, 0)
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
