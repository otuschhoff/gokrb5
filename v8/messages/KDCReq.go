package messages

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.4.1

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/asn1tools"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/asnAppTag"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/types"
)

type marshalKDCReq struct {
	PVNO    int                  `asn1:"explicit,tag:1"`
	MsgType int                  `asn1:"explicit,tag:2"`
	PAData  types.PADataSequence `asn1:"explicit,optional,tag:3"`
	ReqBody asn1.RawValue        `asn1:"explicit,tag:4"`
}

// KDCReqFields represents the KRB_KDC_REQ fields.
type KDCReqFields struct {
	PVNO    int
	MsgType int
	PAData  types.PADataSequence
	ReqBody KDCReqBody
	Renewal bool
}

// ASReq implements RFC 4120 KRB_AS_REQ: https://tools.ietf.org/html/rfc4120#section-5.4.1.
type ASReq struct {
	KDCReqFields
}

// ASReqOptions overrides krb5.conf defaults for a single AS request. Nil
// pointer fields retain the configured value.
type ASReqOptions struct {
	Lifetime         *time.Duration
	RenewLifetime    *time.Duration
	Forwardable      *bool
	Proxiable        *bool
	Canonicalize     *bool
	IncludePAC       *bool
	Addresses        []types.HostAddress
	Enterprise       *bool
	ServicePrincipal *types.PrincipalName
	StartTime        *time.Time
}

// TGSReq implements RFC 4120 KRB_TGS_REQ: https://tools.ietf.org/html/rfc4120#section-5.4.1.
type TGSReq struct {
	KDCReqFields
}

// TGSReqOptions controls Microsoft-specific TGS request behavior.
type TGSReqOptions struct {
	PACOptions        []int
	IncludePAC        *bool
	SupportedEncTypes msflags.SupportedEncTypes
	Forwardable       *bool
	Forwarded         *bool
	Addresses         *types.HostAddresses
}

// S4U2SelfReqOptions controls S4U2self pre-authentication data.
type S4U2SelfReqOptions struct {
	TGSReqOptions
	SubjectCertificate []byte
	PAForUserOnly      bool
}

type marshalKDCReqBody struct {
	KDCOptions  asn1.BitString      `asn1:"explicit,tag:0"`
	CName       types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm       string              `asn1:"generalstring,explicit,tag:2"`
	SName       types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From        time.Time           `asn1:"generalized,explicit,optional,tag:4"`
	Till        time.Time           `asn1:"generalized,explicit,tag:5"`
	RTime       time.Time           `asn1:"generalized,explicit,optional,tag:6"`
	Nonce       int                 `asn1:"explicit,tag:7"`
	EType       []int32             `asn1:"explicit,tag:8"`
	Addresses   []types.HostAddress `asn1:"explicit,optional,tag:9"`
	EncAuthData types.EncryptedData `asn1:"explicit,optional,tag:10"`
	// Ticket needs to be a raw value as it is wrapped in an APPLICATION tag
	AdditionalTickets asn1.RawValue `asn1:"explicit,optional,tag:11"`
}

// KDCReqBody implements the KRB_KDC_REQ request body.
type KDCReqBody struct {
	KDCOptions        asn1.BitString      `asn1:"explicit,tag:0"`
	CName             types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm             string              `asn1:"generalstring,explicit,tag:2"`
	SName             types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From              time.Time           `asn1:"generalized,explicit,optional,tag:4"`
	Till              time.Time           `asn1:"generalized,explicit,tag:5"`
	RTime             time.Time           `asn1:"generalized,explicit,optional,tag:6"`
	Nonce             int                 `asn1:"explicit,tag:7"`
	EType             []int32             `asn1:"explicit,tag:8"`
	Addresses         []types.HostAddress `asn1:"explicit,optional,tag:9"`
	EncAuthData       types.EncryptedData `asn1:"explicit,optional,tag:10"`
	AdditionalTickets []Ticket            `asn1:"explicit,optional,tag:11"`
}

// NewASReqForTGT generates a new KRB_AS_REQ struct for a TGT request.
func NewASReqForTGT(realm string, c *config.Config, cname types.PrincipalName) (ASReq, error) {
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}
	return NewASReq(realm, c, cname, sname)
}

// NewASReqForTGTWithOptions generates a new KRB_AS_REQ struct for a TGT request
// with per-request overrides.
func NewASReqForTGTWithOptions(realm string, c *config.Config, cname types.PrincipalName, options ASReqOptions) (ASReq, error) {
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}
	return NewASReqWithOptions(realm, c, cname, sname, options)
}

// NewASReqForChgPasswd generates a new KRB_AS_REQ struct for a change password request.
func NewASReqForChgPasswd(realm string, c *config.Config, cname types.PrincipalName) (ASReq, error) {
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"kadmin", "changepw"},
	}
	return NewASReq(realm, c, cname, sname)
}

// NewASReq generates a new KRB_AS_REQ struct for a given SNAME.
func NewASReq(realm string, c *config.Config, cname, sname types.PrincipalName) (ASReq, error) {
	return NewASReqWithOptions(realm, c, cname, sname, ASReqOptions{})
}

// NewASReqWithOptions generates a new KRB_AS_REQ struct with per-request
// overrides applied on top of krb5.conf defaults.
func NewASReqWithOptions(realm string, c *config.Config, cname, sname types.PrincipalName, options ASReqOptions) (ASReq, error) {
	nonce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		return ASReq{}, err
	}
	t := time.Now().UTC()
	// Copy the default options to make this thread safe
	kopts := types.NewKrbFlags()
	copy(kopts.Bytes, c.LibDefaults.KDCDefaultOptions.Bytes)
	kopts.BitLength = c.LibDefaults.KDCDefaultOptions.BitLength
	lifetime := c.LibDefaults.TicketLifetime
	if options.Lifetime != nil {
		lifetime = *options.Lifetime
	}
	renewLifetime := c.LibDefaults.RenewLifetime
	if options.RenewLifetime != nil {
		renewLifetime = *options.RenewLifetime
	}
	forwardable := c.LibDefaults.Forwardable
	if options.Forwardable != nil {
		forwardable = *options.Forwardable
	}
	canonicalize := c.LibDefaults.Canonicalize
	if options.Canonicalize != nil {
		canonicalize = *options.Canonicalize
	}
	proxiable := c.LibDefaults.Proxiable
	if options.Proxiable != nil {
		proxiable = *options.Proxiable
	}
	includePAC := c.LibDefaults.RequestPAC
	if options.IncludePAC != nil {
		includePAC = *options.IncludePAC
	}
	if options.Enterprise != nil && *options.Enterprise {
		cname.NameType = nametype.KRB_NT_ENTERPRISE
	}
	if options.ServicePrincipal != nil {
		sname = *options.ServicePrincipal
	}
	a := ASReq{
		KDCReqFields{
			PVNO:    iana.PVNO,
			MsgType: msgtype.KRB_AS_REQ,
			PAData:  types.PADataSequence{},
			ReqBody: KDCReqBody{
				KDCOptions: kopts,
				Realm:      realm,
				CName:      cname,
				SName:      sname,
				Till:       t.Add(lifetime),
				Nonce:      int(nonce.Int64()),
				EType:      c.LibDefaults.DefaultTktEnctypeIDs,
			},
		},
	}
	if forwardable {
		types.SetFlag(&a.ReqBody.KDCOptions, flags.Forwardable)
	}
	if canonicalize {
		types.SetFlag(&a.ReqBody.KDCOptions, flags.Canonicalize)
	}
	if proxiable {
		types.SetFlag(&a.ReqBody.KDCOptions, flags.Proxiable)
	}
	if renewLifetime > 0 {
		types.SetFlag(&a.ReqBody.KDCOptions, flags.Renewable)
		a.ReqBody.RTime = t.Add(renewLifetime)
	}
	if options.StartTime != nil {
		a.ReqBody.From = options.StartTime.UTC()
		a.ReqBody.Till = a.ReqBody.From.Add(lifetime)
		if renewLifetime > 0 {
			a.ReqBody.RTime = a.ReqBody.From.Add(renewLifetime)
		}
	}
	if options.Addresses != nil {
		a.ReqBody.Addresses = append([]types.HostAddress(nil), options.Addresses...)
	} else if !c.LibDefaults.NoAddresses {
		ha, err := types.LocalHostAddresses()
		if err != nil {
			return a, fmt.Errorf("could not get local addresses: %v", err)
		}
		ha = append(ha, types.HostAddressesFromNetIPs(c.LibDefaults.ExtraAddresses)...)
		a.ReqBody.Addresses = ha
	}
	pacRequest, err := types.NewKerbPAPACRequestPAData(includePAC)
	if err != nil {
		return a, fmt.Errorf("could not marshal KERB-PA-PAC-REQUEST: %v", err)
	}
	a.PAData = append(a.PAData, pacRequest)
	return a, nil
}

// NewTGSReq generates a new KRB_TGS_REQ struct.
func NewTGSReq(cname types.PrincipalName, kdcRealm string, c *config.Config, tgt Ticket, sessionKey types.EncryptionKey, sname types.PrincipalName, renewal bool) (TGSReq, error) {
	return NewTGSReqWithOptions(cname, kdcRealm, c, tgt, sessionKey, sname, renewal, TGSReqOptions{})
}

// NewTGSReqWithOptions generates a new KRB_TGS_REQ with Microsoft-specific options.
func NewTGSReqWithOptions(cname types.PrincipalName, kdcRealm string, c *config.Config, tgt Ticket, sessionKey types.EncryptionKey, sname types.PrincipalName, renewal bool, options TGSReqOptions) (TGSReq, error) {
	a, err := tgsReq(cname, sname, kdcRealm, renewal, c, options)
	if err != nil {
		return a, err
	}
	if err := a.setPAData(tgt, sessionKey); err != nil {
		return a, err
	}
	return a, a.addMSKILEPAData(c, options)
}

// NewS4U2SelfTGSReq generates an S4U2self request for a service ticket to sname.
func NewS4U2SelfTGSReq(cname types.PrincipalName, kdcRealm string, c *config.Config, tgt Ticket, sessionKey types.EncryptionKey, sname, user types.PrincipalName, userRealm string, options S4U2SelfReqOptions) (TGSReq, error) {
	if len(options.SubjectCertificate) > 0 {
		if _, err := x509.ParseCertificate(options.SubjectCertificate); err != nil {
			return TGSReq{}, fmt.Errorf("invalid S4U subject certificate: %v", err)
		}
	}
	a, err := tgsReq(cname, sname, kdcRealm, false, c, options.TGSReqOptions)
	if err != nil {
		return a, err
	}
	if err := a.setPAData(tgt, sessionKey); err != nil {
		return a, err
	}
	paForUser, err := NewPAForUserPAData(user, userRealm, sessionKey)
	if err != nil {
		return a, err
	}
	a.PAData = append(a.PAData, paForUser)
	if !options.PAForUserOnly && supportsS4UX509(sessionKey.KeyType) {
		s4uOptions := types.NewKrbFlags()
		types.SetFlag(&s4uOptions, flags.S4UOptionUseReplyKeyUsage)
		x509, err := NewPAS4UX509UserPAData(types.S4UUserID{
			Nonce:              uint32(a.ReqBody.Nonce),
			CName:              user,
			CRealm:             userRealm,
			SubjectCertificate: append([]byte(nil), options.SubjectCertificate...),
			Options:            s4uOptions,
		}, sessionKey)
		if err != nil {
			return a, err
		}
		a.PAData = append(a.PAData, x509)
	}
	return a, a.addMSKILEPAData(c, options.TGSReqOptions)
}

// NewS4U2ProxyTGSReq generates an S4U2proxy request using an evidence ticket.
func NewS4U2ProxyTGSReq(cname types.PrincipalName, kdcRealm string, c *config.Config, tgt Ticket, sessionKey types.EncryptionKey, sname types.PrincipalName, evidence Ticket, options TGSReqOptions) (TGSReq, error) {
	a, err := tgsReq(cname, sname, kdcRealm, false, c, options)
	if err != nil {
		return a, err
	}
	a.ReqBody.AdditionalTickets = []Ticket{evidence}
	types.SetFlag(&a.ReqBody.KDCOptions, flags.CNameInAddlTkt)
	if err := a.setPAData(tgt, sessionKey); err != nil {
		return a, err
	}
	return a, a.addMSKILEPAData(c, options)
}

func supportsS4UX509(keyType int32) bool {
	switch keyType {
	case etypeID.DES_CBC_CRC, etypeID.DES_CBC_MD4, etypeID.DES_CBC_MD5, etypeID.RC4_HMAC:
		return false
	default:
		return true
	}
}

// NewUser2UserTGSReq returns a TGS-REQ suitable for user-to-user authentication (https://tools.ietf.org/html/rfc4120#section-3.7)
func NewUser2UserTGSReq(cname types.PrincipalName, kdcRealm string, c *config.Config, clientTGT Ticket, sessionKey types.EncryptionKey, sname types.PrincipalName, renewal bool, verifyingTGT Ticket) (TGSReq, error) {
	return NewUser2UserTGSReqWithOptions(cname, kdcRealm, c, clientTGT, sessionKey, sname, renewal, verifyingTGT, TGSReqOptions{})
}

// NewUser2UserTGSReqWithOptions returns a user-to-user TGS-REQ with Microsoft-specific options.
func NewUser2UserTGSReqWithOptions(cname types.PrincipalName, kdcRealm string, c *config.Config, clientTGT Ticket, sessionKey types.EncryptionKey, sname types.PrincipalName, renewal bool, verifyingTGT Ticket, options TGSReqOptions) (TGSReq, error) {
	a, err := tgsReq(cname, sname, kdcRealm, renewal, c, options)
	if err != nil {
		return a, err
	}
	a.ReqBody.AdditionalTickets = []Ticket{verifyingTGT}
	types.SetFlag(&a.ReqBody.KDCOptions, flags.EncTktInSkey)
	if err := a.setPAData(clientTGT, sessionKey); err != nil {
		return a, err
	}
	return a, a.addMSKILEPAData(c, options)
}

// tgsReq populates the fields for a TGS_REQ
func tgsReq(cname, sname types.PrincipalName, kdcRealm string, renewal bool, c *config.Config, options TGSReqOptions) (TGSReq, error) {
	nonce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		return TGSReq{}, err
	}
	t := time.Now().UTC()
	k := KDCReqFields{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_TGS_REQ,
		ReqBody: KDCReqBody{
			KDCOptions: types.NewKrbFlags(),
			Realm:      kdcRealm,
			CName:      cname, // Add the CName to make validation of the reply easier
			SName:      sname,
			Till:       t.Add(c.LibDefaults.TicketLifetime),
			Nonce:      int(nonce.Int64()),
			EType:      preferredTGSEnctypes(c.LibDefaults.DefaultTGSEnctypeIDs, options.SupportedEncTypes),
		},
		Renewal: renewal,
	}
	if c.LibDefaults.Forwardable {
		types.SetFlag(&k.ReqBody.KDCOptions, flags.Forwardable)
	}
	if options.Forwardable != nil {
		if *options.Forwardable {
			types.SetFlag(&k.ReqBody.KDCOptions, flags.Forwardable)
		} else {
			types.UnsetFlag(&k.ReqBody.KDCOptions, flags.Forwardable)
		}
	}
	if options.Forwarded != nil {
		if *options.Forwarded {
			types.SetFlag(&k.ReqBody.KDCOptions, flags.Forwarded)
		} else {
			types.UnsetFlag(&k.ReqBody.KDCOptions, flags.Forwarded)
		}
	}
	if c.LibDefaults.Canonicalize {
		types.SetFlag(&k.ReqBody.KDCOptions, flags.Canonicalize)
	}
	if c.LibDefaults.Proxiable {
		types.SetFlag(&k.ReqBody.KDCOptions, flags.Proxiable)
	}
	if c.LibDefaults.RenewLifetime > time.Duration(0) {
		types.SetFlag(&k.ReqBody.KDCOptions, flags.Renewable)
		k.ReqBody.RTime = t.Add(c.LibDefaults.RenewLifetime)
	}
	if options.Addresses != nil {
		k.ReqBody.Addresses = append([]types.HostAddress(nil), (*options.Addresses)...)
	} else if !c.LibDefaults.NoAddresses {
		ha, err := types.LocalHostAddresses()
		if err != nil {
			return TGSReq{}, fmt.Errorf("could not get local addresses: %v", err)
		}
		ha = append(ha, types.HostAddressesFromNetIPs(c.LibDefaults.ExtraAddresses)...)
		k.ReqBody.Addresses = ha
	}
	if renewal {
		types.SetFlag(&k.ReqBody.KDCOptions, flags.Renew)
		types.SetFlag(&k.ReqBody.KDCOptions, flags.Renewable)
	}
	return TGSReq{
		k,
	}, nil
}

func preferredTGSEnctypes(configured []int32, supported msflags.SupportedEncTypes) []int32 {
	etypes := append([]int32(nil), configured...)
	if supported&msflags.SupportedEncTypeAES256CTSHMACSHA196SK == 0 {
		return etypes
	}
	for i, etype := range etypes {
		if etype != etypeID.AES256_CTS_HMAC_SHA1_96 || i == 0 {
			continue
		}
		copy(etypes[1:i+1], etypes[:i])
		etypes[0] = etypeID.AES256_CTS_HMAC_SHA1_96
		break
	}
	return etypes
}

func (k *TGSReq) addMSKILEPAData(c *config.Config, options TGSReqOptions) error {
	includePAC := c.LibDefaults.RequestPAC
	if options.IncludePAC != nil {
		includePAC = *options.IncludePAC
	}
	pacRequest, err := types.NewKerbPAPACRequestPAData(includePAC)
	if err != nil {
		return fmt.Errorf("could not marshal KERB-PA-PAC-REQUEST: %v", err)
	}
	k.PAData = append(k.PAData, pacRequest)

	pacOptions := append([]int(nil), options.PACOptions...)
	pacOptions = appendPACOption(pacOptions, flags.PACOptionBranchAware)
	if options.SupportedEncTypes&msflags.SupportedEncTypeClaims != 0 {
		pacOptions = appendPACOption(pacOptions, flags.PACOptionClaims)
	}
	pa, err := types.NewPAPACOptionsPAData(pacOptions...)
	if err != nil {
		return fmt.Errorf("could not marshal PA-PAC-OPTIONS: %v", err)
	}
	k.PAData = append(k.PAData, pa)
	return nil
}

func appendPACOption(options []int, option int) []int {
	for _, existing := range options {
		if existing == option {
			return options
		}
	}
	return append(options, option)
}

func (k *TGSReq) setPAData(tgt Ticket, sessionKey types.EncryptionKey) error {
	_, _, err := k.setPADataWithSubkey(tgt, sessionKey, false)
	return err
}

// SetPADataWithSubkey rebuilds PA-TGS-REQ with an authenticator subkey and
// returns the subkey and encoded AP-REQ for use as implicit FAST armor.
func (k *TGSReq) SetPADataWithSubkey(tgt Ticket, sessionKey types.EncryptionKey) (types.EncryptionKey, []byte, error) {
	return k.setPADataWithSubkey(tgt, sessionKey, true)
}

func (k *TGSReq) setPADataWithSubkey(tgt Ticket, sessionKey types.EncryptionKey, includeSubkey bool) (types.EncryptionKey, []byte, error) {
	// Marshal the request and calculate checksum
	b, err := k.ReqBody.Marshal()
	if err != nil {
		return types.EncryptionKey{}, nil, krberror.Errorf(err, krberror.EncodingError, "error marshaling TGS_REQ body")
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return types.EncryptionKey{}, nil, krberror.Errorf(err, krberror.EncryptingError, "error getting etype to encrypt authenticator")
	}
	cb, err := etype.GetChecksumHash(sessionKey.KeyValue, b, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		return types.EncryptionKey{}, nil, krberror.Errorf(err, krberror.ChksumError, "error getting etype checksum hash")
	}

	// Form PAData for TGS_REQ
	// Create authenticator
	auth, err := types.NewAuthenticator(tgt.Realm, k.ReqBody.CName)
	if err != nil {
		return types.EncryptionKey{}, nil, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}
	auth.Cksum = types.Checksum{
		CksumType: etype.GetHashID(),
		Checksum:  cb,
	}
	if includeSubkey {
		if err := auth.GenerateSeqNumberAndSubKey(sessionKey.KeyType, etype.GetKeyByteSize()); err != nil {
			return types.EncryptionKey{}, nil, krberror.Errorf(err, krberror.KRBMsgError, "error generating TGS authenticator subkey")
		}
	}
	// Create AP_REQ
	apReq, err := NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		return types.EncryptionKey{}, nil, krberror.Errorf(err, krberror.KRBMsgError, "error generating new AP_REQ")
	}
	apb, err := apReq.Marshal()
	if err != nil {
		return types.EncryptionKey{}, nil, krberror.Errorf(err, krberror.EncodingError, "error marshaling AP_REQ for pre-authentication data")
	}
	paData := types.PADataSequence{{
		PADataType:  patype.PA_TGS_REQ,
		PADataValue: apb,
	}}
	for _, pa := range k.PAData {
		if pa.PADataType != patype.PA_TGS_REQ {
			paData = append(paData, pa)
		}
	}
	k.PAData = paData
	return auth.SubKey, apb, nil
}

// Unmarshal bytes b into the ASReq struct.
func (k *ASReq) Unmarshal(b []byte) error {
	var m marshalKDCReq
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.ASREQ))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling AS_REQ")
	}
	expectedMsgType := msgtype.KRB_AS_REQ
	if m.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a AS_REQ. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}
	var reqb KDCReqBody
	err = reqb.Unmarshal(m.ReqBody.Bytes)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error processing AS_REQ body")
	}
	k.MsgType = m.MsgType
	k.PAData = m.PAData
	k.PVNO = m.PVNO
	k.ReqBody = reqb
	return nil
}

// Unmarshal bytes b into the TGSReq struct.
func (k *TGSReq) Unmarshal(b []byte) error {
	var m marshalKDCReq
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.TGSREQ))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling TGS_REQ")
	}
	expectedMsgType := msgtype.KRB_TGS_REQ
	if m.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a TGS_REQ. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}
	var reqb KDCReqBody
	err = reqb.Unmarshal(m.ReqBody.Bytes)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error processing TGS_REQ body")
	}
	k.MsgType = m.MsgType
	k.PAData = m.PAData
	k.PVNO = m.PVNO
	k.ReqBody = reqb
	return nil
}

// Unmarshal bytes b into the KRB_KDC_REQ body struct.
func (k *KDCReqBody) Unmarshal(b []byte) error {
	var m marshalKDCReqBody
	_, err := asn1.Unmarshal(b, &m)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling KDC_REQ body")
	}
	k.KDCOptions = m.KDCOptions
	if len(k.KDCOptions.Bytes) < 4 {
		tb := make([]byte, 4-len(k.KDCOptions.Bytes))
		k.KDCOptions.Bytes = append(tb, k.KDCOptions.Bytes...)
		k.KDCOptions.BitLength = len(k.KDCOptions.Bytes) * 8
	}
	k.CName = m.CName
	k.Realm = m.Realm
	k.SName = m.SName
	k.From = m.From
	k.Till = m.Till
	k.RTime = m.RTime
	k.Nonce = m.Nonce
	k.EType = m.EType
	k.Addresses = m.Addresses
	k.EncAuthData = m.EncAuthData
	if len(m.AdditionalTickets.Bytes) > 0 {
		k.AdditionalTickets, err = unmarshalTicketsSequence(m.AdditionalTickets)
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling additional tickets")
		}
	}
	return nil
}

// Marshal ASReq struct.
func (k *ASReq) Marshal() ([]byte, error) {
	m := marshalKDCReq{
		PVNO:    k.PVNO,
		MsgType: k.MsgType,
		PAData:  k.PAData,
	}
	b, err := k.ReqBody.Marshal()
	if err != nil {
		var mk []byte
		return mk, err
	}
	m.ReqBody = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        4,
		Bytes:      b,
	}
	mk, err := asn1.Marshal(m)
	if err != nil {
		return mk, krberror.Errorf(err, krberror.EncodingError, "error marshaling AS_REQ")
	}
	mk = asn1tools.AddASNAppTag(mk, asnAppTag.ASREQ)
	return mk, nil
}

// Marshal TGSReq struct.
func (k *TGSReq) Marshal() ([]byte, error) {
	m := marshalKDCReq{
		PVNO:    k.PVNO,
		MsgType: k.MsgType,
		PAData:  k.PAData,
	}
	b, err := k.ReqBody.Marshal()
	if err != nil {
		var mk []byte
		return mk, err
	}
	m.ReqBody = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        4,
		Bytes:      b,
	}
	mk, err := asn1.Marshal(m)
	if err != nil {
		return mk, krberror.Errorf(err, krberror.EncodingError, "error marshaling AS_REQ")
	}
	mk = asn1tools.AddASNAppTag(mk, asnAppTag.TGSREQ)
	return mk, nil
}

// Marshal KRB_KDC_REQ body struct.
func (k *KDCReqBody) Marshal() ([]byte, error) {
	var b []byte
	m := marshalKDCReqBody{
		KDCOptions:  k.KDCOptions,
		CName:       k.CName,
		Realm:       k.Realm,
		SName:       k.SName,
		From:        k.From,
		Till:        k.Till,
		RTime:       k.RTime,
		Nonce:       k.Nonce,
		EType:       k.EType,
		Addresses:   k.Addresses,
		EncAuthData: k.EncAuthData,
	}
	rawtkts, err := MarshalTicketSequence(k.AdditionalTickets)
	if err != nil {
		return b, krberror.Errorf(err, krberror.EncodingError, "error in marshaling KDC request body additional tickets")
	}
	//The asn1.rawValue needs the tag setting on it for where it is in the KDCReqBody
	rawtkts.Tag = 11
	if len(rawtkts.Bytes) > 0 {
		m.AdditionalTickets = rawtkts
	}
	b, err = asn1.Marshal(m)
	if err != nil {
		return b, krberror.Errorf(err, krberror.EncodingError, "error in marshaling KDC request body")
	}
	return b, nil
}
