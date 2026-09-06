package types

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
)

// KerbPAPACRequest controls whether the KDC includes a PAC in the ticket.
type KerbPAPACRequest struct {
	IncludePAC bool `asn1:"explicit,tag:0"`
}

// PAPACOptions carries the MS-KILE PAC option flags.
type PAPACOptions struct {
	Options asn1.BitString `asn1:"explicit,tag:0"`
}

// KerbErrorData carries typed data in a KRB-ERROR e-data field.
type KerbErrorData struct {
	DataType  int32  `asn1:"explicit,tag:1"`
	DataValue []byte `asn1:"explicit,optional,tag:2"`
}

// KerbExtError is the fixed-width little-endian extended error payload.
type KerbExtError struct {
	Status   ntstatus.Code
	Reserved uint32
	Flags    uint32
}

// KerbADRestrictionEntry carries an application-server restriction.
type KerbADRestrictionEntry struct {
	RestrictionType int32  `asn1:"explicit,tag:0"`
	Restriction     []byte `asn1:"explicit,tag:1"`
}

// LSAPTokenInfoIntegrity is the current MS-KILE token integrity payload.
type LSAPTokenInfoIntegrity struct {
	Flags              msflags.TokenInfoFlags
	TokenIL            msflags.TokenIntegrityLevel
	PerBootMachineID   [32]byte
	CrossBootMachineID [32]byte
}

// ADAuthDataAPOptions is a little-endian KERB-AD-AUTH-DATA-AP-OPTIONS mask.
type ADAuthDataAPOptions msflags.APOptions

// PAForUser carries the S4U2self user identity and checksum.
type PAForUser struct {
	UserName    PrincipalName `asn1:"explicit,tag:0"`
	UserRealm   string        `asn1:"generalstring,explicit,tag:1"`
	Cksum       Checksum      `asn1:"explicit,tag:2"`
	AuthPackage string        `asn1:"generalstring,explicit,tag:3"`
}

// S4UUserID identifies a user by principal or certificate.
type S4UUserID struct {
	Nonce              uint32
	CName              PrincipalName
	CRealm             string
	SubjectCertificate []byte
	Options            asn1.BitString
}

type s4UUserIDWire struct {
	Nonce              int64          `asn1:"explicit,tag:0"`
	CName              PrincipalName  `asn1:"explicit,optional,tag:1"`
	CRealm             string         `asn1:"generalstring,explicit,tag:2"`
	SubjectCertificate []byte         `asn1:"explicit,optional,tag:3"`
	Options            asn1.BitString `asn1:"explicit,optional,tag:4"`
}

// PAS4UX509User carries an S4U certificate identity and its checksum.
type PAS4UX509User struct {
	UserID   asn1.RawValue `asn1:"explicit,tag:0"`
	Checksum Checksum      `asn1:"explicit,tag:1"`
}

// PASupportedEncTypes is the little-endian supported-encryption-types mask.
type PASupportedEncTypes msflags.SupportedEncTypes

// KerbKeyListReq requests keys for the listed encryption types.
type KerbKeyListReq []int32

// KerbKeyListRep contains keys supplied by the KDC.
type KerbKeyListRep []EncryptionKey

// PASvrReferralData is the Windows referral structure retained for compatibility.
type PASvrReferralData struct {
	ReferredName  PrincipalName `asn1:"explicit,optional,tag:1"`
	ReferredRealm string        `asn1:"generalstring,explicit,tag:0"`
}

// KerbSupersededByUser names the principal replacing a migrated account.
type KerbSupersededByUser struct {
	Name  PrincipalName `asn1:"explicit,tag:0"`
	Realm string        `asn1:"generalstring,explicit,tag:1"`
}

// KerbDMSAKeyPackage contains current and previous keys for a delegated MSA.
type KerbDMSAKeyPackage struct {
	CurrentKeys        KerbKeyListRep `asn1:"explicit,tag:0"`
	PreviousKeys       KerbKeyListRep `asn1:"explicit,optional,tag:1"`
	ExpirationInterval time.Time      `asn1:"generalized,explicit,tag:2"`
	FetchInterval      time.Time      `asn1:"generalized,explicit,tag:4"`
}

func marshalMSKILE(v interface{}) ([]byte, error) {
	return asn1.Marshal(v)
}

func unmarshalMSKILE(b []byte, v interface{}) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing ASN.1 data: %d bytes", len(rest))
	}
	return nil
}

func marshalPAData(paType int32, value interface{}) (PAData, error) {
	b, err := marshalMSKILE(value)
	return PAData{PADataType: paType, PADataValue: b}, err
}

func getPAData(pa *PAData, expected int32, value interface{}) error {
	if pa.PADataType != expected {
		return fmt.Errorf("PAData type mismatch: expected %d, got %d", expected, pa.PADataType)
	}
	return unmarshalMSKILE(pa.PADataValue, value)
}

func (v *KerbPAPACRequest) Marshal() ([]byte, error) { return marshalMSKILE(*v) }
func (v *KerbPAPACRequest) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }
func (v *PAPACOptions) Marshal() ([]byte, error) {
	if v.Options.BitLength < 32 {
		return nil, fmt.Errorf("PA-PAC-OPTIONS must contain at least 32 bits")
	}
	return marshalMSKILE(*v)
}
func (v *PAPACOptions) Unmarshal(b []byte) error {
	if err := unmarshalMSKILE(b, v); err != nil {
		return err
	}
	if v.Options.BitLength < 32 {
		return fmt.Errorf("PA-PAC-OPTIONS must contain at least 32 bits")
	}
	return nil
}
func (v *KerbErrorData) Marshal() ([]byte, error)          { return marshalMSKILE(*v) }
func (v *KerbErrorData) Unmarshal(b []byte) error          { return unmarshalMSKILE(b, v) }
func (v *KerbADRestrictionEntry) Marshal() ([]byte, error) { return marshalMSKILE(*v) }
func (v *KerbADRestrictionEntry) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }
func (v *PAForUser) Marshal() ([]byte, error)              { return marshalMSKILE(*v) }
func (v *PAForUser) Unmarshal(b []byte) error              { return unmarshalMSKILE(b, v) }
func (v *PASvrReferralData) Marshal() ([]byte, error)      { return marshalMSKILE(*v) }
func (v *PASvrReferralData) Unmarshal(b []byte) error      { return unmarshalMSKILE(b, v) }
func (v *KerbSupersededByUser) Marshal() ([]byte, error)   { return marshalMSKILE(*v) }
func (v *KerbSupersededByUser) Unmarshal(b []byte) error   { return unmarshalMSKILE(b, v) }
func (v *KerbDMSAKeyPackage) Marshal() ([]byte, error)     { return marshalMSKILE(*v) }
func (v *KerbDMSAKeyPackage) Unmarshal(b []byte) error     { return unmarshalMSKILE(b, v) }
func (v *KerbKeyListReq) Marshal() ([]byte, error)         { return marshalMSKILE(*v) }
func (v *KerbKeyListReq) Unmarshal(b []byte) error         { return unmarshalMSKILE(b, v) }
func (v *KerbKeyListRep) Marshal() ([]byte, error)         { return marshalMSKILE(*v) }
func (v *KerbKeyListRep) Unmarshal(b []byte) error         { return unmarshalMSKILE(b, v) }

func (v *KerbExtError) Marshal() ([]byte, error) {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:4], uint32(v.Status))
	binary.LittleEndian.PutUint32(b[4:8], v.Reserved)
	binary.LittleEndian.PutUint32(b[8:12], v.Flags)
	return b, nil
}

func (v *KerbExtError) Unmarshal(b []byte) error {
	if len(b) != 12 {
		return fmt.Errorf("KERB-EXT-ERROR must be 12 bytes, got %d", len(b))
	}
	v.Status = ntstatus.Code(binary.LittleEndian.Uint32(b[0:4]))
	v.Reserved = binary.LittleEndian.Uint32(b[4:8])
	v.Flags = binary.LittleEndian.Uint32(b[8:12])
	return nil
}

func NewKerbExtErrorData(v KerbExtError) (KerbErrorData, error) {
	b, err := v.Marshal()
	return KerbErrorData{DataType: int32(msflags.KERB_ERR_TYPE_EXTENDED), DataValue: b}, err
}

func (v *KerbErrorData) GetKerbExtError() (ext KerbExtError, err error) {
	if v.DataType != int32(msflags.KERB_ERR_TYPE_EXTENDED) {
		return ext, fmt.Errorf("KERB-ERROR-DATA type mismatch: expected %d, got %d", msflags.KERB_ERR_TYPE_EXTENDED, v.DataType)
	}
	err = ext.Unmarshal(v.DataValue)
	return
}

func (v *LSAPTokenInfoIntegrity) Marshal() ([]byte, error) {
	b := make([]byte, 72)
	binary.LittleEndian.PutUint32(b[0:4], uint32(v.Flags))
	binary.LittleEndian.PutUint32(b[4:8], uint32(v.TokenIL))
	copy(b[8:40], v.PerBootMachineID[:])
	copy(b[40:72], v.CrossBootMachineID[:])
	return b, nil
}

func (v *LSAPTokenInfoIntegrity) Unmarshal(b []byte) error {
	if len(b) != 72 {
		return fmt.Errorf("LSAP_TOKEN_INFO_INTEGRITY must be 72 bytes, got %d", len(b))
	}
	v.Flags = msflags.TokenInfoFlags(binary.LittleEndian.Uint32(b[0:4]))
	v.TokenIL = msflags.TokenIntegrityLevel(binary.LittleEndian.Uint32(b[4:8]))
	copy(v.PerBootMachineID[:], b[8:40])
	copy(v.CrossBootMachineID[:], b[40:72])
	return nil
}

func NewKerbADRestrictionEntryForToken(v LSAPTokenInfoIntegrity) (KerbADRestrictionEntry, error) {
	b, err := v.Marshal()
	return KerbADRestrictionEntry{RestrictionType: msflags.KerbADRestrictionTypeTokenIntegrity, Restriction: b}, err
}

func (v *KerbADRestrictionEntry) GetLSAPTokenInfoIntegrity() (info LSAPTokenInfoIntegrity, err error) {
	if v.RestrictionType != msflags.KerbADRestrictionTypeTokenIntegrity {
		return info, fmt.Errorf("unsupported KERB-AD-RESTRICTION-ENTRY type %d", v.RestrictionType)
	}
	err = info.Unmarshal(v.Restriction)
	return
}

func (v ADAuthDataAPOptions) Marshal() ([]byte, error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b, nil
}

func (v *ADAuthDataAPOptions) Unmarshal(b []byte) error {
	if len(b) != 4 {
		return fmt.Errorf("KERB-AD-AUTH-DATA-AP-OPTIONS must be 4 bytes, got %d", len(b))
	}
	*v = ADAuthDataAPOptions(binary.LittleEndian.Uint32(b))
	return nil
}

func (v PASupportedEncTypes) Marshal() ([]byte, error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b, nil
}

func (v *PASupportedEncTypes) Unmarshal(b []byte) error {
	if len(b) != 4 {
		return fmt.Errorf("PA-SUPPORTED-ENCTYPES must be 4 bytes, got %d", len(b))
	}
	*v = PASupportedEncTypes(binary.LittleEndian.Uint32(b))
	return nil
}

func (v *S4UUserID) Marshal() ([]byte, error) {
	if v.Options.BitLength > 0 && v.Options.BitLength < 32 {
		return nil, fmt.Errorf("S4UUserID options must contain at least 32 bits")
	}
	w := s4UUserIDWire{
		Nonce:              int64(v.Nonce),
		CName:              v.CName,
		CRealm:             v.CRealm,
		SubjectCertificate: v.SubjectCertificate,
		Options:            v.Options,
	}
	return marshalMSKILE(w)
}

func (v *S4UUserID) Unmarshal(b []byte) error {
	var w s4UUserIDWire
	if err := unmarshalMSKILE(b, &w); err != nil {
		return err
	}
	if w.Nonce < 0 || w.Nonce > int64(^uint32(0)) {
		return fmt.Errorf("S4UUserID nonce out of range: %d", w.Nonce)
	}
	v.Nonce = uint32(w.Nonce)
	v.CName = w.CName
	v.CRealm = w.CRealm
	v.SubjectCertificate = w.SubjectCertificate
	v.Options = w.Options
	if v.Options.BitLength > 0 && v.Options.BitLength < 32 {
		return fmt.Errorf("S4UUserID options must contain at least 32 bits")
	}
	return nil
}

func (v *PAS4UX509User) Marshal() ([]byte, error) { return marshalMSKILE(*v) }
func (v *PAS4UX509User) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// NewPAS4UX509User embeds a DER-encoded S4UUserID in PA-S4U-X509-USER.
func NewPAS4UX509User(userID S4UUserID, checksum Checksum) (PAS4UX509User, error) {
	b, err := userID.Marshal()
	if err != nil {
		return PAS4UX509User{}, err
	}
	return PAS4UX509User{
		UserID:   asn1.RawValue{Class: asn1.ClassContextSpecific, IsCompound: true, Tag: 0, Bytes: b},
		Checksum: checksum,
	}, nil
}

// GetUserID decodes the S4UUserID carried by PA-S4U-X509-USER.
func (v *PAS4UX509User) GetUserID() (S4UUserID, error) {
	var userID S4UUserID
	err := userID.Unmarshal(v.UserID.Bytes)
	return userID, err
}

func NewKerbPAPACRequestPAData(include bool) (PAData, error) {
	return marshalPAData(patype.PA_PAC_REQUEST, KerbPAPACRequest{IncludePAC: include})
}

func (pa *PAData) GetKerbPAPACRequest() (v KerbPAPACRequest, err error) {
	err = getPAData(pa, patype.PA_PAC_REQUEST, &v)
	return
}

func NewPAPACOptionsPAData(bits ...int) (PAData, error) {
	options := NewKrbFlags()
	for _, bit := range bits {
		if bit < 0 || bit >= options.BitLength {
			return PAData{}, fmt.Errorf("PA-PAC-OPTIONS bit out of range: %d", bit)
		}
		SetFlag(&options, bit)
	}
	return marshalPAData(patype.PA_PAC_OPTIONS, PAPACOptions{Options: options})
}

func (pa *PAData) GetPAPACOptions() (v PAPACOptions, err error) {
	err = getPAData(pa, patype.PA_PAC_OPTIONS, &v)
	return
}

func NewPAForUserPAData(v PAForUser) (PAData, error) {
	return marshalPAData(patype.PA_FOR_USER, v)
}

func (pa *PAData) GetPAForUser() (v PAForUser, err error) {
	err = getPAData(pa, patype.PA_FOR_USER, &v)
	return
}

func NewPAS4UX509UserPAData(v PAS4UX509User) (PAData, error) {
	return marshalPAData(patype.PA_S4U_X509_USER, v)
}

func (pa *PAData) GetPAS4UX509User() (v PAS4UX509User, err error) {
	err = getPAData(pa, patype.PA_S4U_X509_USER, &v)
	return
}

func NewPASupportedEncTypesPAData(v PASupportedEncTypes) (PAData, error) {
	b, err := v.Marshal()
	return PAData{PADataType: patype.PA_SUPPORTED_ETYPES, PADataValue: b}, err
}

func (pa *PAData) GetPASupportedEncTypes() (v PASupportedEncTypes, err error) {
	if pa.PADataType != patype.PA_SUPPORTED_ETYPES {
		return v, fmt.Errorf("PAData type mismatch: expected %d, got %d", patype.PA_SUPPORTED_ETYPES, pa.PADataType)
	}
	err = v.Unmarshal(pa.PADataValue)
	return
}

func NewKerbKeyListReqPAData(v KerbKeyListReq) (PAData, error) {
	return marshalPAData(patype.PA_KERB_KEY_LIST_REQ, v)
}

func (pa *PAData) GetKerbKeyListReq() (v KerbKeyListReq, err error) {
	err = getPAData(pa, patype.PA_KERB_KEY_LIST_REQ, &v)
	return
}

func NewKerbKeyListRepPAData(v KerbKeyListRep) (PAData, error) {
	return marshalPAData(patype.PA_KERB_KEY_LIST_REP, v)
}

func (pa *PAData) GetKerbKeyListRep() (v KerbKeyListRep, err error) {
	err = getPAData(pa, patype.PA_KERB_KEY_LIST_REP, &v)
	return
}

func NewPASvrReferralInfoPAData(v PASvrReferralData) (PAData, error) {
	return marshalPAData(patype.PA_SVR_REFERRAL_INFO, v)
}

func (pa *PAData) GetPASvrReferralInfo() (v PASvrReferralData, err error) {
	err = getPAData(pa, patype.PA_SVR_REFERRAL_INFO, &v)
	return
}

func NewKerbSupersededByUserPAData(v KerbSupersededByUser) (PAData, error) {
	return marshalPAData(patype.PA_SUPERSEDED_BY_USER, v)
}

func (pa *PAData) GetKerbSupersededByUser() (v KerbSupersededByUser, err error) {
	err = getPAData(pa, patype.PA_SUPERSEDED_BY_USER, &v)
	return
}

func NewKerbDMSAKeyPackagePAData(v KerbDMSAKeyPackage) (PAData, error) {
	return marshalPAData(patype.PA_DMSA_KEY_PACKAGE, v)
}

func (pa *PAData) GetKerbDMSAKeyPackage() (v KerbDMSAKeyPackage, err error) {
	err = getPAData(pa, patype.PA_DMSA_KEY_PACKAGE, &v)
	return
}

func NewKerbADRestrictionEntry(v KerbADRestrictionEntry) (AuthorizationDataEntry, error) {
	b, err := v.Marshal()
	return AuthorizationDataEntry{ADType: adtype.KerbAdRestrictionEntry, ADData: b}, err
}

func (a *AuthorizationDataEntry) GetKerbADRestrictionEntry() (v KerbADRestrictionEntry, err error) {
	if a.ADType != adtype.KerbAdRestrictionEntry {
		return v, fmt.Errorf("authorization-data type mismatch: expected %d, got %d", adtype.KerbAdRestrictionEntry, a.ADType)
	}
	err = v.Unmarshal(a.ADData)
	return
}

func NewKerbLocalEntry() AuthorizationDataEntry {
	return AuthorizationDataEntry{ADType: adtype.KerbLocal}
}

func (a *AuthorizationDataEntry) IsKerbLocal() bool {
	return a.ADType == adtype.KerbLocal && len(a.ADData) == 0
}

func NewADAuthDataAPOptionsEntry(options msflags.APOptions) (AuthorizationDataEntry, error) {
	v := ADAuthDataAPOptions(options)
	b, err := v.Marshal()
	return AuthorizationDataEntry{ADType: adtype.ADAuthDataAPOptions, ADData: b}, err
}

func (a *AuthorizationDataEntry) GetADAuthDataAPOptions() (v ADAuthDataAPOptions, err error) {
	if a.ADType != adtype.ADAuthDataAPOptions {
		return v, fmt.Errorf("authorization-data type mismatch: expected %d, got %d", adtype.ADAuthDataAPOptions, a.ADType)
	}
	err = v.Unmarshal(a.ADData)
	return
}

func NewKerbDMSAKeyPackageEntry(v KerbDMSAKeyPackage) (AuthorizationDataEntry, error) {
	b, err := v.Marshal()
	return AuthorizationDataEntry{ADType: adtype.KerbDMSAKeyPackage, ADData: b}, err
}

func (a *AuthorizationDataEntry) GetKerbDMSAKeyPackage() (v KerbDMSAKeyPackage, err error) {
	if a.ADType != adtype.KerbDMSAKeyPackage {
		return v, fmt.Errorf("authorization-data type mismatch: expected %d, got %d", adtype.KerbDMSAKeyPackage, a.ADType)
	}
	err = v.Unmarshal(a.ADData)
	return
}
