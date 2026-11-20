// Package types provides Kerberos 5 data types.
package types

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/asn1tools"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/asnAppTag"
)

const (
	authenticatorSequenceMask = 0x3fffffff
	microsecondsPerSecond     = int64(time.Second / time.Microsecond)
)

// Authenticator - A record containing information that can be shown to have been recently generated using the session
// key known only by the client and server.
// https://tools.ietf.org/html/rfc4120#section-5.5.1
type Authenticator struct {
	AVNO              int               `asn1:"explicit,tag:0"`
	CRealm            string            `asn1:"generalstring,explicit,tag:1"`
	CName             PrincipalName     `asn1:"explicit,tag:2"`
	Cksum             Checksum          `asn1:"explicit,optional,tag:3"`
	Cusec             int               `asn1:"explicit,tag:4"`
	CTime             time.Time         `asn1:"generalized,explicit,tag:5"`
	SubKey            EncryptionKey     `asn1:"explicit,optional,tag:6"`
	SeqNumber         int64             `asn1:"explicit,optional,tag:7"`
	AuthorizationData AuthorizationData `asn1:"explicit,optional,tag:8"`
}

// NewAuthenticator creates a new Authenticator.
func NewAuthenticator(realm string, cname PrincipalName) (Authenticator, error) {
	seq, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return Authenticator{}, fmt.Errorf("generate authenticator sequence number: %w", err)
	}
	t := time.Now().UTC()
	var checksum Checksum
	var subkey EncryptionKey
	return Authenticator{
		AVNO:              iana.PVNO,
		CRealm:            realm,
		CName:             cname,
		Cksum:             checksum,
		Cusec:             microsecondOffset(t),
		CTime:             t,
		SubKey:            subkey,
		SeqNumber:         seq.Int64() & authenticatorSequenceMask,
		AuthorizationData: nil,
	}, nil
}

func microsecondOffset(t time.Time) int {
	return int(t.UnixNano()/int64(time.Microsecond) - t.Unix()*microsecondsPerSecond)
}

// GenerateSeqNumberAndSubKey sets the Authenticator's sequence number and subkey.
func (a *Authenticator) GenerateSeqNumberAndSubKey(keyType int32, keySize int) error {
	seq, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return fmt.Errorf("generate authenticator sequence number: %w", err)
	}
	a.SeqNumber = seq.Int64() & authenticatorSequenceMask
	// Generate subkey value
	sk := make([]byte, keySize)
	if _, err := rand.Read(sk); err != nil {
		return fmt.Errorf("generate authenticator subkey: %w", err)
	}
	a.SubKey = EncryptionKey{
		KeyType:  keyType,
		KeyValue: sk,
	}
	return nil
}

// Unmarshal bytes into the Authenticator.
func (a *Authenticator) Unmarshal(b []byte) error {
	params := fmt.Sprintf("application,explicit,tag:%v", asnAppTag.Authenticator)
	if _, err := asn1.UnmarshalWithParams(b, a, params); err != nil {
		return fmt.Errorf("decode authenticator: %w", err)
	}
	return nil
}

// Marshal the Authenticator.
func (a *Authenticator) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*a)
	if err != nil {
		return nil, fmt.Errorf("encode authenticator: %w", err)
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.Authenticator)
	return b, nil
}
