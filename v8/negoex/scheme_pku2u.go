package negoex

import (
	"github.com/otuschhoff/gokrb5/v8/gssapi"
)

// PKU2UAuthScheme is the on-wire GUID 235f69ad-73fb-4dbc-8203-0629e739339b.
var PKU2UAuthScheme = AuthScheme{0xad, 0x69, 0x5f, 0x23, 0xfb, 0x73, 0xbc, 0x4d, 0x82, 0x03, 0x06, 0x29, 0xe7, 0x39, 0x33, 0x9b}

// PKU2UMechanism is the interface required by the PKU2U NEGOEX adapter.
type PKU2UMechanism interface {
	gssapi.ContextMechanism
	QueryMetadata(target string, initiator bool) ([]byte, error)
	ExchangeMetadata(metadata []byte, initiator bool) error
}

type pku2uScheme struct {
	mechanism PKU2UMechanism
}

// NewPKU2UScheme adapts a PKU2U context mechanism to a NEGOEX auth scheme.
func NewPKU2UScheme(mechanism PKU2UMechanism) MetadataScheme {
	return &pku2uScheme{mechanism: mechanism}
}

func (*pku2uScheme) AuthScheme() AuthScheme { return PKU2UAuthScheme }

func (scheme *pku2uScheme) InitSecContext(target string, input []byte) ([]byte, gssapi.Context, bool, error) {
	return scheme.mechanism.InitSecContext(target, input)
}

func (scheme *pku2uScheme) AcceptSecContext(input []byte) ([]byte, gssapi.Context, bool, error) {
	return scheme.mechanism.AcceptSecContext(input)
}

func (scheme *pku2uScheme) QueryMetadata(target string, initiator bool) ([]byte, error) {
	return scheme.mechanism.QueryMetadata(target, initiator)
}

func (scheme *pku2uScheme) ExchangeMetadata(metadata []byte, initiator bool) error {
	return scheme.mechanism.ExchangeMetadata(metadata, initiator)
}
