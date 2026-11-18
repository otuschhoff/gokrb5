package gssapi

import (
	"crypto/md5" // #nosec G501 -- RFC 4121 section 4.1.1.2 fixes the channel-binding digest.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
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
func gssUint32Length(name string, length int) (uint32, error) {
	if length < 0 || uint64(length) > uint64(^uint32(0)) { // #nosec G115 -- nonnegative and bounded before conversion.
		return 0, fmt.Errorf("%s length %d exceeds uint32 range", name, length)
	}
	return uint32(length), nil // #nosec G115 -- bounded by uint32 range above.
}

func gssUint16Length(name string, length int) (uint16, error) {
	if length < 0 || length > int(^uint16(0)) {
		return 0, fmt.Errorf("%s length %d exceeds uint16 range", name, length)
	}
	return uint16(length), nil
}

// MD5Hash returns the RFC 4121 channel-binding digest.
func (c ChannelBindings) MD5Hash() [md5.Size]byte {
	b := make([]byte, 0, 20+len(c.InitiatorAddress.Address)+len(c.AcceptorAddress.Address)+len(c.ApplicationData))
	b = appendChannelBindingAddress(b, c.InitiatorAddress)
	b = appendChannelBindingAddress(b, c.AcceptorAddress)
	applicationLength, err := gssUint32Length("application data", len(c.ApplicationData))
	if err != nil {
		return md5.Sum(nil) // #nosec G401 -- preserves the existing MD5Hash fallback value.
	}
	b = appendUint32LE(b, applicationLength)
	b = append(b, c.ApplicationData...)
	return md5.Sum(b) // #nosec G401 -- RFC 4121 specifies this field inside the authenticated checksum.
}

func appendChannelBindingAddress(b []byte, address ChannelBindingAddress) []byte {
	b = appendUint32LE(b, address.AddressType)
	length, err := gssUint32Length("channel binding address", len(address.Address))
	if err != nil {
		return b
	}
	b = appendUint32LE(b, length)
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
	case x509.UnknownSignatureAlgorithm, x509.MD2WithRSA, x509.MD5WithRSA,
		x509.SHA1WithRSA, x509.SHA256WithRSA, x509.DSAWithSHA1, x509.DSAWithSHA256,
		x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS,
		x509.PureEd25519:
		digest = sha256.New()
	default:
		// Future x509.SignatureAlgorithm values retain the RFC 5929 SHA-256 default.
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
