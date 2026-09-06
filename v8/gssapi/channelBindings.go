package gssapi

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"hash"
)

// ChannelBindingAddress is a GSS channel-binding address.
type ChannelBindingAddress struct {
	AddressType uint32
	Address     []byte
}

// ChannelBindings contains the initiator, acceptor, and application data
// protected by the RFC 4121 authenticator checksum.
type ChannelBindings struct {
	InitiatorAddress ChannelBindingAddress
	AcceptorAddress  ChannelBindingAddress
	ApplicationData  []byte
}

// MD5Hash returns the RFC 4121 channel-binding digest.
func (c ChannelBindings) MD5Hash() [md5.Size]byte {
	b := make([]byte, 0, 20+len(c.InitiatorAddress.Address)+len(c.AcceptorAddress.Address)+len(c.ApplicationData))
	b = appendChannelBindingAddress(b, c.InitiatorAddress)
	b = appendChannelBindingAddress(b, c.AcceptorAddress)
	b = appendUint32LE(b, uint32(len(c.ApplicationData)))
	b = append(b, c.ApplicationData...)
	return md5.Sum(b)
}

func appendChannelBindingAddress(b []byte, address ChannelBindingAddress) []byte {
	b = appendUint32LE(b, address.AddressType)
	b = appendUint32LE(b, uint32(len(address.Address)))
	return append(b, address.Address...)
}

func appendUint32LE(b []byte, value uint32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return append(b, encoded[:]...)
}

// TLSServerEndPoint creates a tls-server-end-point channel binding.
func TLSServerEndPoint(state tls.ConnectionState) (ChannelBindings, error) {
	if len(state.PeerCertificates) == 0 {
		return ChannelBindings{}, errors.New("TLS connection has no peer certificate")
	}
	certificate := state.PeerCertificates[0]
	var digest hash.Hash
	switch certificate.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		digest = sha512.New384()
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		digest = sha512.New()
	default:
		digest = sha256.New()
	}
	_, _ = digest.Write(certificate.Raw)
	return ChannelBindings{ApplicationData: append([]byte("tls-server-end-point:"), digest.Sum(nil)...)}, nil
}

// TLSUnique creates a tls-unique channel binding from the TLS Finished data.
func TLSUnique(state tls.ConnectionState) (ChannelBindings, error) {
	if len(state.TLSUnique) == 0 {
		return ChannelBindings{}, errors.New("TLS connection does not expose tls-unique data")
	}
	return ChannelBindings{ApplicationData: append([]byte("tls-unique:"), state.TLSUnique...)}, nil
}
