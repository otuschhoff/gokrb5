package pkinit

import (
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"
	"testing"

	forkasn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"
)

// This test-only prototype covers the GeneralString fields, not the enclosing
// PKINIT principal. It preserves octets without interpreting their encoding.
const generalStringTag = 27

func generalString(value string) asn1.RawValue {
	return asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: generalStringTag, IsCompound: false,
		Bytes: []byte(value), FullBytes: nil,
	}
}

func parseGeneralString(value asn1.RawValue) (string, error) {
	if value.Class != asn1.ClassUniversal || value.Tag != generalStringTag || value.IsCompound {
		return "", asn1.StructuralError{Msg: "expected primitive generalstring"}
	}
	return string(value.Bytes), nil
}

func marshalGeneralStrings(values []string) ([]byte, error) {
	raw := make([]asn1.RawValue, len(values))
	for i, value := range values {
		raw[i] = generalString(value)
	}
	der, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("encode principal components: %w", err)
	}
	return der, nil
}

func unmarshalGeneralStrings(der []byte) ([]string, error) {
	var raw []asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("decode principal components: %w", err)
	}
	if len(rest) != 0 {
		return nil, asn1.StructuralError{Msg: "trailing data after principal components"}
	}
	values := make([]string, len(raw))
	for i, value := range raw {
		values[i], err = parseGeneralString(value)
		if err != nil {
			return nil, fmt.Errorf("decode principal component %d: %w", i, err)
		}
	}
	return values, nil
}

func TestGeneralStringPrototypeParity(t *testing.T) {
	t.Parallel()

	for _, name := range []struct {
		label      string
		realm      string
		components []string
	}{
		{label: "service", realm: "EXAMPLE.COM", components: []string{"host", "server.example.com"}},
		{label: "empty fields", realm: "", components: []string{""}},
		{label: "no components", realm: "EXAMPLE.COM", components: nil},
		{label: "opaque octets", realm: "R\x00\xff", components: []string{"\xff", "caf\xc3\xa9"}},
		{label: "length boundary", realm: strings.Repeat("R", 128), components: []string{
			strings.Repeat("a", 127), strings.Repeat("b", 128),
		}},
	} {
		t.Run(name.label, func(t *testing.T) {
			t.Parallel()

			// Extract the [0] realm and nested [1] component sequence from
			// the actual fork-encoded PKINIT principal.
			legacy, err := forkasn1.Marshal(principal(name.realm, 1, name.components...))
			require.NoError(t, err)
			var envelope struct {
				Realm     asn1.RawValue `asn1:"explicit,tag:0"`
				Principal struct {
					NameType   int32         `asn1:"explicit,tag:0"`
					Components asn1.RawValue `asn1:"explicit,tag:1"`
				} `asn1:"explicit,tag:1"`
			}
			rest, err := asn1.Unmarshal(legacy, &envelope)
			require.NoError(t, err)
			require.Empty(t, rest)

			realmDER, err := asn1.Marshal(generalString(name.realm))
			require.NoError(t, err)
			require.Equal(t, envelope.Realm.Bytes, realmDER)
			var raw asn1.RawValue
			rest, err = asn1.Unmarshal(envelope.Realm.Bytes, &raw)
			require.NoError(t, err)
			require.Empty(t, rest)
			realm, err := parseGeneralString(raw)
			require.NoError(t, err)
			require.Equal(t, name.realm, realm)

			componentsDER, err := marshalGeneralStrings(name.components)
			require.NoError(t, err)
			require.Equal(t, envelope.Principal.Components.Bytes, componentsDER)
			components, err := unmarshalGeneralStrings(envelope.Principal.Components.Bytes)
			require.NoError(t, err)
			require.True(t, slices.Equal(name.components, components))
		})
	}
}

func TestGeneralStringPrototypeRejectsMalformedDER(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		der  string
	}{
		{name: "truncated component", der: "\x30\x02\x1b\x01"},
		{name: "constructed string", der: "\x30\x02\x3b\x00"},
		{name: "wrong tag class", der: "\x30\x02\x9b\x00"},
		{name: "nonminimal length", der: "\x30\x03\x1b\x81\x00"},
		{name: "trailing data", der: "\x30\x00\x05\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := unmarshalGeneralStrings([]byte(tc.der))
			require.Error(t, err)
		})
	}
}

func TestGeneralStringPrototypeDiffersOnLegacyStringTags(t *testing.T) {
	t.Parallel()

	// The fork accepts PrintableString for a principal component. The
	// prototype only accepts the required GeneralString tag.
	const principalDER = "\x30\x16\xa0\x03\x1b\x01R\xa1\x0f" +
		"\x30\x0d\xa0\x03\x02\x01\x01\xa1\x06\x30\x04\x13\x02ab"
	var legacy KRB5PrincipalName
	require.NoError(t, strictUnmarshal([]byte(principalDER), &legacy))
	require.Equal(t, []string{"ab"}, legacy.PrincipalName.NameString)

	_, err := unmarshalGeneralStrings([]byte("\x30\x04\x13\x02ab"))
	require.ErrorContains(t, err, "expected primitive generalstring")
}
