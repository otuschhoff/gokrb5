package spnego

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/asn1tools"
	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/asnAppTag"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/service"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// GSSAPI KRB5 MechToken IDs.
const (
	TOK_ID_KRB_AP_REQ = "0100"
	TOK_ID_KRB_AP_REP = "0200"
	TOK_ID_KRB_ERROR  = "0300"
)

// KRB5Token context token implementation for GSSAPI.
type KRB5Token struct {
	OID      asn1.ObjectIdentifier
	tokID    []byte
	APReq    messages.APReq
	APRep    messages.APRep
	KRBError messages.KRBError
	settings *service.Settings
	context  context.Context
	raw      bool
	checksum gssapi.AuthenticatorChecksum
	replyKey types.EncryptionKey
	expectedAuthenticator types.Authenticator
}

// KRB5TokenAPREQOptions controls AP-REQ context establishment behavior.
type KRB5TokenAPREQOptions struct {
	GSSAPIFlags        []int
	APOptions          []int
	ChannelBindings    *gssapi.ChannelBindings
	DelegatedCredential []byte
	Delegate            bool
	ForceDelegation     bool
	DelegationAddresses types.HostAddresses
}

// Marshal a KRB5Token into a slice of bytes.
func (m *KRB5Token) Marshal() ([]byte, error) {
	if m.raw {
		switch hex.EncodeToString(m.tokID) {
		case TOK_ID_KRB_AP_REQ:
			return m.APReq.Marshal()
		case TOK_ID_KRB_AP_REP:
			return m.APRep.Marshal()
		default:
			return nil, errors.New("raw Kerberos token has unsupported token type")
		}
	}
	// Create the header
	b, _ := asn1.Marshal(m.OID)
	b = append(b, m.tokID...)
	var tb []byte
	var err error
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		tb, err = m.APReq.Marshal()
		if err != nil {
			return []byte{}, fmt.Errorf("error marshalling AP_REQ for MechToken: %v", err)
		}
	case TOK_ID_KRB_AP_REP:
		tb, err = m.APRep.Marshal()
		if err != nil {
			return nil, fmt.Errorf("error marshalling AP_REP for MechToken: %v", err)
		}
	case TOK_ID_KRB_ERROR:
		return []byte{}, errors.New("marshal of KRB_ERROR GSSAPI MechToken not supported by gokrb5")
	}
	if err != nil {
		return []byte{}, fmt.Errorf("error mashalling kerberos message within mech token: %v", err)
	}
	b = append(b, tb...)
	return asn1tools.AddASNAppTag(b, 0), nil
}

// Unmarshal a KRB5Token.
func (m *KRB5Token) Unmarshal(b []byte) error {
	if len(b) > 0 && b[0] == byte(0x60+asnAppTag.APREQ) {
		m.raw = true
		m.tokID, _ = hex.DecodeString(TOK_ID_KRB_AP_REQ)
		return m.APReq.Unmarshal(b)
	}
	if len(b) > 0 && b[0] == byte(0x60+asnAppTag.APREP) {
		m.raw = true
		m.tokID, _ = hex.DecodeString(TOK_ID_KRB_AP_REP)
		return m.APRep.Unmarshal(b)
	}
	var oid asn1.ObjectIdentifier
	r, err := asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
	if err != nil {
		return fmt.Errorf("error unmarshalling KRB5Token OID: %v", err)
	}
	if !oid.Equal(gssapi.OIDKRB5.OID()) {
		return fmt.Errorf("error unmarshalling KRB5Token, OID is %s not %s", oid.String(), gssapi.OIDKRB5.OID().String())
	}
	m.OID = oid
	if len(r) < 2 {
		return fmt.Errorf("krb5token too short")
	}
	m.tokID = r[0:2]
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		var a messages.APReq
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REQ: %v", err)
		}
		m.APReq = a
	case TOK_ID_KRB_AP_REP:
		var a messages.APRep
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REP: %v", err)
		}
		m.APRep = a
	case TOK_ID_KRB_ERROR:
		var a messages.KRBError
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token KRBError: %v", err)
		}
		m.KRBError = a
	}
	return nil
}

// Verify a KRB5Token.
func (m *KRB5Token) Verify() (bool, gssapi.Status) {
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		result, err := service.VerifyAPREQWithResult(&m.APReq, m.settings)
		if err != nil {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}
		m.checksum = result.Checksum
		m.expectedAuthenticator = m.APReq.Authenticator
		m.replyKey = m.APReq.Ticket.DecryptedEncPart.Key
		if len(m.APReq.Authenticator.SubKey.KeyValue) > 0 {
			m.replyKey = m.APReq.Authenticator.SubKey
		}
		m.context = context.Background()
		m.context = context.WithValue(m.context, ctxCredentials, result.Credentials)
		return true, gssapi.Status{Code: gssapi.StatusComplete}
	case TOK_ID_KRB_AP_REP:
		if len(m.replyKey.KeyValue) == 0 {
			return false, gssapi.Status{Code: gssapi.StatusNoContext, Message: "AP_REP verification state is missing"}
		}
		if err := m.APRep.Verify(m.expectedAuthenticator, m.replyKey); err != nil {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}
		return true, gssapi.Status{Code: gssapi.StatusComplete}
	case TOK_ID_KRB_ERROR:
		if m.KRBError.MsgType != msgtype.KRB_ERROR {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "KRB5_Error token not valid"}
		}
		return true, gssapi.Status{Code: gssapi.StatusUnavailable}
	}
	return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "unknown TOK_ID in KRB5 token"}
}

// IsAPReq tests if the MechToken contains an AP_REQ.
func (m *KRB5Token) IsAPReq() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REQ {
		return true
	}
	return false
}

// IsAPRep tests if the MechToken contains an AP_REP.
func (m *KRB5Token) IsAPRep() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REP {
		return true
	}
	return false
}

// IsKRBError tests if the MechToken contains an KRB_ERROR.
func (m *KRB5Token) IsKRBError() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_ERROR {
		return true
	}
	return false
}

// Context returns the KRB5 token's context which will contain any verify user identity information.
func (m *KRB5Token) Context() context.Context {
	return m.context
}

// NewKRB5TokenAPREQ creates a new KRB5 token with AP_REQ
func NewKRB5TokenAPREQ(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, GSSAPIFlags []int, APOptions []int) (KRB5Token, error) {
	return NewKRB5TokenAPREQWithOptions(cl, tkt, sessionKey, KRB5TokenAPREQOptions{
		GSSAPIFlags: GSSAPIFlags,
		APOptions:   APOptions,
	})
}

// NewKRB5TokenAPREQWithOptions creates a KRB5 AP-REQ token with channel
// bindings and optional delegated credentials.
func NewKRB5TokenAPREQWithOptions(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, options KRB5TokenAPREQOptions) (KRB5Token, error) {
	// TODO consider providing the SPN rather than the specific tkt and key and get these from the krb client.
	var m KRB5Token
	m.OID = gssapi.OIDKRB5.OID()
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
	m.tokID = tb

	gssFlags := append([]int(nil), options.GSSAPIFlags...)
	delegatedCredential := append([]byte(nil), options.DelegatedCredential...)
	if options.Delegate {
		if len(delegatedCredential) > 0 {
			return m, errors.New("delegated credential cannot be supplied when automatic delegation is requested")
		}
		var err error
		delegatedCredential, err = cl.GetDelegatedCredential(tkt, sessionKey, options.DelegationAddresses, options.ForceDelegation)
		if err != nil {
			return m, err
		}
		gssFlags = appendContextFlag(gssFlags, gssapi.ContextFlagDeleg)
	}
	checksum := gssapi.NewAuthenticatorChecksum(options.ChannelBindings, gssFlags...)
	if len(delegatedCredential) > 0 {
		if checksum.Flags&gssapi.ContextFlagDeleg == 0 {
			return m, errors.New("delegated credential requires GSS_C_DELEG_FLAG")
		}
		checksum.DelegationOption = 1
		checksum.Deleg = delegatedCredential
	}
	auth, err := krb5TokenAuthenticatorWithChecksum(cl.Credentials, checksum)
	if err != nil {
		return m, err
	}
	if options.ChannelBindings != nil {
		entry, err := types.NewADAuthDataAPOptionsEntry(msflags.KERB_AP_OPTIONS_CBT)
		if err != nil {
			return m, err
		}
		encoded, err := asn1.Marshal(types.AuthorizationData{entry})
		if err != nil {
			return m, err
		}
		auth.AuthorizationData = append(auth.AuthorizationData, types.AuthorizationDataEntry{ADType: adtype.ADIfRelevant, ADData: encoded})
	}
	et, err := krbcrypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return m, err
	}
	if err := auth.GenerateSeqNumberAndSubKey(sessionKey.KeyType, et.GetKeyByteSize()); err != nil {
		return m, err
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		auth,
	)
	if err != nil {
		return m, err
	}
	for _, o := range options.APOptions {
		types.SetFlag(&APReq.APOptions, o)
	}
	if checksum.Flags&(gssapi.ContextFlagMutual|gssapi.ContextFlagDCEStyle) != 0 {
		types.SetFlag(&APReq.APOptions, flags.APOptionMutualRequired)
	}
	APReq.Authenticator = auth
	m.APReq = APReq
	return m, nil
}

// NewKRB5TokenAPREP creates a KRB5 mechanism token containing an AP-REP.
func NewKRB5TokenAPREP(rep messages.APRep, raw bool) KRB5Token {
	tokID, _ := hex.DecodeString(TOK_ID_KRB_AP_REP)
	return KRB5Token{OID: gssapi.OIDKRB5.OID(), tokID: tokID, APRep: rep, raw: raw}
}

func appendContextFlag(contextFlags []int, flag int) []int {
	for _, existing := range contextFlags {
		if existing == flag {
			return contextFlags
		}
	}
	return append(contextFlags, flag)
}

// krb5TokenAuthenticator creates a new kerberos authenticator for kerberos MechToken
func krb5TokenAuthenticator(creds *credentials.Credentials, flags []int) (types.Authenticator, error) {
	return krb5TokenAuthenticatorWithChecksum(creds, gssapi.NewAuthenticatorChecksum(nil, flags...))
}

func krb5TokenAuthenticatorWithChecksum(creds *credentials.Credentials, checksum gssapi.AuthenticatorChecksum) (types.Authenticator, error) {
	//RFC 4121 Section 4.1.1
	auth, err := types.NewAuthenticator(creds.Domain(), creds.CName())
	if err != nil {
		return auth, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}
	checksumBytes, err := checksum.Marshal()
	if err != nil {
		return auth, krberror.Errorf(err, krberror.EncodingError, "error encoding GSSAPI authenticator checksum")
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  checksumBytes,
	}
	return auth, nil
}

// Create new authenticator checksum for kerberos MechToken
func newAuthenticatorChksum(flags []int) []byte {
	checksum := gssapi.NewAuthenticatorChecksum(nil, flags...)
	if checksum.Flags&gssapi.ContextFlagDeleg != 0 {
		checksum.DelegationOption = 1
	}
	b, _ := checksum.Marshal()
	return b
}
