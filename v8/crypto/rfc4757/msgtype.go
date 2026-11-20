package rfc4757

import (
	"encoding/binary"

	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
)

const messageTypeBytes = 4

// UsageToMSMsgType maps Kerberos key usages to Microsoft message types.
// It retains the historical four-byte buffer and unsigned varint encoding.
func UsageToMSMsgType(usage uint32) []byte {
	// Translate usage numbers to the Microsoft T numbers
	switch usage {
	case keyusage.AS_REP_ENCPART, keyusage.TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY:
		usage = keyusage.TGS_REP_ENCPART_SESSION_KEY
	case keyusage.GSSAPI_ACCEPTOR_SIGN:
		usage = keyusage.KRB_PRIV_ENCPART
	}
	// Now convert to bytes
	tb := make([]byte, messageTypeBytes)
	binary.PutUvarint(tb, uint64(usage))
	return tb
}
