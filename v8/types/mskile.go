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
	b, err := asn1.Marshal(v)
	if err != nil {
		return b, fmt.Errorf("encode ASN.1 %T: %w", v, err)
	}
	return b, nil
}

func unmarshalMSKILE(b []byte, v interface{}) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return fmt.Errorf("decode ASN.1 into %T: %w", v, err)
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

// Marshal marshals KerbPAPACRequest to its DER encoding.
func (v *KerbPAPACRequest) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KerbPAPACRequest.
func (v *KerbPAPACRequest) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals PAPACOptions to its DER encoding.
func (v *PAPACOptions) Marshal() ([]byte, error) {
	if v.Options.BitLength < 32 {
		return nil, fmt.Errorf("PA-PAC-OPTIONS must contain at least 32 bits")
	}
	return marshalMSKILE(*v)
}

// Unmarshal unmarshals DER bytes into PAPACOptions.
func (v *PAPACOptions) Unmarshal(b []byte) error {
	if err := unmarshalMSKILE(b, v); err != nil {
		return err
	}
	if v.Options.BitLength < 32 {
		return fmt.Errorf("PA-PAC-OPTIONS must contain at least 32 bits")
	}
	return nil
}

// Marshal marshals KerbErrorData to its DER encoding.
func (v *KerbErrorData) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KerbErrorData.
func (v *KerbErrorData) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals KerbADRestrictionEntry to its DER encoding.
func (v *KerbADRestrictionEntry) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KerbADRestrictionEntry.
func (v *KerbADRestrictionEntry) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals PAForUser to its DER encoding.
func (v *PAForUser) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into PAForUser.
func (v *PAForUser) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals PASvrReferralData to its DER encoding.
func (v *PASvrReferralData) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into PASvrReferralData.
func (v *PASvrReferralData) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals KerbSupersededByUser to its DER encoding.
func (v *KerbSupersededByUser) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KerbSupersededByUser.
func (v *KerbSupersededByUser) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals KerbDMSAKeyPackage to its DER encoding.
func (v *KerbDMSAKeyPackage) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KerbDMSAKeyPackage.
func (v *KerbDMSAKeyPackage) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals KerbKeyListReq to its DER encoding.
func (v *KerbKeyListReq) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KerbKeyListReq.
func (v *KerbKeyListReq) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals KerbKeyListRep to its DER encoding.
func (v *KerbKeyListRep) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KerbKeyListRep.
func (v *KerbKeyListRep) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals KerbExtError to its DER encoding.
func (v *KerbExtError) Marshal() ([]byte, error) {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:4], uint32(v.Status))
	binary.LittleEndian.PutUint32(b[4:8], v.Reserved)
	binary.LittleEndian.PutUint32(b[8:12], v.Flags)
	return b, nil
}

// Unmarshal unmarshals DER bytes into KerbExtError.
func (v *KerbExtError) Unmarshal(b []byte) error {
	if len(b) != 12 {
		return fmt.Errorf("KERB-EXT-ERROR must be 12 bytes, got %d", len(b))
	}
	v.Status = ntstatus.Code(binary.LittleEndian.Uint32(b[0:4]))
	v.Reserved = binary.LittleEndian.Uint32(b[4:8])
	v.Flags = binary.LittleEndian.Uint32(b[8:12])
	return nil
}

// NewKerbExtErrorData wraps an extended error in KERB-ERROR-DATA.
func NewKerbExtErrorData(v KerbExtError) (KerbErrorData, error) {
	b, err := v.Marshal()
	return KerbErrorData{DataType: int32(msflags.KERB_ERR_TYPE_EXTENDED), DataValue: b}, err
}

// GetKerbExtError decodes the KerbExtError carried by the value.
func (v *KerbErrorData) GetKerbExtError() (KerbExtError, error) {
	var ext KerbExtError
	var err error
	if v.DataType != int32(msflags.KERB_ERR_TYPE_EXTENDED) {
		return ext, fmt.Errorf("KERB-ERROR-DATA type mismatch: expected %d, got %d", msflags.KERB_ERR_TYPE_EXTENDED, v.DataType)
	}
	err = ext.Unmarshal(v.DataValue)
	return ext, err
}

// Marshal marshals LSAPTokenInfoIntegrity to its DER encoding.
func (v *LSAPTokenInfoIntegrity) Marshal() ([]byte, error) {
	b := make([]byte, 72)
	binary.LittleEndian.PutUint32(b[0:4], uint32(v.Flags))
	binary.LittleEndian.PutUint32(b[4:8], uint32(v.TokenIL))
	copy(b[8:40], v.PerBootMachineID[:])
	copy(b[40:72], v.CrossBootMachineID[:])
	return b, nil
}

// Unmarshal unmarshals DER bytes into LSAPTokenInfoIntegrity.
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

// NewKerbADRestrictionEntryForToken builds a restriction entry carrying LSAP_TOKEN_INFO_INTEGRITY.
func NewKerbADRestrictionEntryForToken(v LSAPTokenInfoIntegrity) (KerbADRestrictionEntry, error) {
	b, err := v.Marshal()
	return KerbADRestrictionEntry{RestrictionType: msflags.KerbADRestrictionTypeTokenIntegrity, Restriction: b}, err
}

// GetLSAPTokenInfoIntegrity decodes the LSAPTokenInfoIntegrity carried by the value.
func (v *KerbADRestrictionEntry) GetLSAPTokenInfoIntegrity() (LSAPTokenInfoIntegrity, error) {
	var info LSAPTokenInfoIntegrity
	var err error
	if v.RestrictionType != msflags.KerbADRestrictionTypeTokenIntegrity {
		return info, fmt.Errorf("unsupported KERB-AD-RESTRICTION-ENTRY type %d", v.RestrictionType)
	}
	err = info.Unmarshal(v.Restriction)
	return info, err
}

// Marshal marshals ADAuthDataAPOptions to its DER encoding.
func (v ADAuthDataAPOptions) Marshal() ([]byte, error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b, nil
}

// Unmarshal unmarshals DER bytes into ADAuthDataAPOptions.
func (v *ADAuthDataAPOptions) Unmarshal(b []byte) error {
	if len(b) != 4 {
		return fmt.Errorf("KERB-AD-AUTH-DATA-AP-OPTIONS must be 4 bytes, got %d", len(b))
	}
	*v = ADAuthDataAPOptions(binary.LittleEndian.Uint32(b))
	return nil
}

// Marshal marshals PASupportedEncTypes to its DER encoding.
func (v PASupportedEncTypes) Marshal() ([]byte, error) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b, nil
}

// Unmarshal unmarshals DER bytes into PASupportedEncTypes.
func (v *PASupportedEncTypes) Unmarshal(b []byte) error {
	if len(b) != 4 {
		return fmt.Errorf("PA-SUPPORTED-ENCTYPES must be 4 bytes, got %d", len(b))
	}
	*v = PASupportedEncTypes(binary.LittleEndian.Uint32(b))
	return nil
}

// Marshal marshals S4UUserID to its DER encoding.
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

// Unmarshal unmarshals DER bytes into S4UUserID.
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

// Marshal marshals PAS4UX509User to its DER encoding.
func (v *PAS4UX509User) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into PAS4UX509User.
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

// NewKerbPAPACRequestPAData wraps KerbPAPACRequest in a PA-DATA entry of its assigned type.
func NewKerbPAPACRequestPAData(include bool) (PAData, error) {
	return marshalPAData(patype.PA_PAC_REQUEST, KerbPAPACRequest{IncludePAC: include})
}

// GetKerbPAPACRequest decodes the KerbPAPACRequest carried by the value.
func (pa *PAData) GetKerbPAPACRequest() (KerbPAPACRequest, error) {
	var v KerbPAPACRequest
	var err error
	err = getPAData(pa, patype.PA_PAC_REQUEST, &v)
	return v, err
}

// NewPAPACOptionsPAData wraps PAPACOptions in a PA-DATA entry of its assigned type.
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

// GetPAPACOptions decodes the PAPACOptions carried by the value.
func (pa *PAData) GetPAPACOptions() (PAPACOptions, error) {
	var v PAPACOptions
	var err error
	err = getPAData(pa, patype.PA_PAC_OPTIONS, &v)
	return v, err
}

// NewPAForUserPAData wraps PAForUser in a PA-DATA entry of its assigned type.
func NewPAForUserPAData(v PAForUser) (PAData, error) {
	return marshalPAData(patype.PA_FOR_USER, v)
}

// GetPAForUser decodes the PAForUser carried by the value.
func (pa *PAData) GetPAForUser() (PAForUser, error) {
	var v PAForUser
	var err error
	err = getPAData(pa, patype.PA_FOR_USER, &v)
	return v, err
}

// NewPAS4UX509UserPAData wraps PAS4UX509User in a PA-DATA entry of its assigned type.
func NewPAS4UX509UserPAData(v PAS4UX509User) (PAData, error) {
	return marshalPAData(patype.PA_S4U_X509_USER, v)
}

// GetPAS4UX509User decodes the PAS4UX509User carried by the value.
func (pa *PAData) GetPAS4UX509User() (PAS4UX509User, error) {
	var v PAS4UX509User
	var err error
	err = getPAData(pa, patype.PA_S4U_X509_USER, &v)
	return v, err
}

// NewPASupportedEncTypesPAData wraps PASupportedEncTypes in a PA-DATA entry of its assigned type.
func NewPASupportedEncTypesPAData(v PASupportedEncTypes) (PAData, error) {
	b, err := v.Marshal()
	return PAData{PADataType: patype.PA_SUPPORTED_ETYPES, PADataValue: b}, err
}

// GetPASupportedEncTypes decodes the PASupportedEncTypes carried by the value.
func (pa *PAData) GetPASupportedEncTypes() (PASupportedEncTypes, error) {
	var v PASupportedEncTypes
	var err error
	if pa.PADataType != patype.PA_SUPPORTED_ETYPES {
		return v, fmt.Errorf("PAData type mismatch: expected %d, got %d", patype.PA_SUPPORTED_ETYPES, pa.PADataType)
	}
	err = v.Unmarshal(pa.PADataValue)
	return v, err
}

// NewKerbKeyListReqPAData wraps KerbKeyListReq in a PA-DATA entry of its assigned type.
func NewKerbKeyListReqPAData(v KerbKeyListReq) (PAData, error) {
	return marshalPAData(patype.PA_KERB_KEY_LIST_REQ, v)
}

// GetKerbKeyListReq decodes the KerbKeyListReq carried by the value.
func (pa *PAData) GetKerbKeyListReq() (KerbKeyListReq, error) {
	var v KerbKeyListReq
	var err error
	err = getPAData(pa, patype.PA_KERB_KEY_LIST_REQ, &v)
	return v, err
}

// NewKerbKeyListRepPAData wraps KerbKeyListRep in a PA-DATA entry of its assigned type.
func NewKerbKeyListRepPAData(v KerbKeyListRep) (PAData, error) {
	return marshalPAData(patype.PA_KERB_KEY_LIST_REP, v)
}

// GetKerbKeyListRep decodes the KerbKeyListRep carried by the value.
func (pa *PAData) GetKerbKeyListRep() (KerbKeyListRep, error) {
	var v KerbKeyListRep
	var err error
	err = getPAData(pa, patype.PA_KERB_KEY_LIST_REP, &v)
	return v, err
}

// NewPASvrReferralInfoPAData wraps PASvrReferralInfo in a PA-DATA entry of its assigned type.
func NewPASvrReferralInfoPAData(v PASvrReferralData) (PAData, error) {
	return marshalPAData(patype.PA_SVR_REFERRAL_INFO, v)
}

// GetPASvrReferralInfo decodes the PASvrReferralInfo carried by the value.
func (pa *PAData) GetPASvrReferralInfo() (PASvrReferralData, error) {
	var v PASvrReferralData
	var err error
	err = getPAData(pa, patype.PA_SVR_REFERRAL_INFO, &v)
	return v, err
}

// NewKerbSupersededByUserPAData wraps KerbSupersededByUser in a PA-DATA entry of its assigned type.
func NewKerbSupersededByUserPAData(v KerbSupersededByUser) (PAData, error) {
	return marshalPAData(patype.PA_SUPERSEDED_BY_USER, v)
}

// GetKerbSupersededByUser decodes the KerbSupersededByUser carried by the value.
func (pa *PAData) GetKerbSupersededByUser() (KerbSupersededByUser, error) {
	var v KerbSupersededByUser
	var err error
	err = getPAData(pa, patype.PA_SUPERSEDED_BY_USER, &v)
	return v, err
}

// NewKerbDMSAKeyPackagePAData wraps KerbDMSAKeyPackage in a PA-DATA entry of its assigned type.
func NewKerbDMSAKeyPackagePAData(v KerbDMSAKeyPackage) (PAData, error) {
	return marshalPAData(patype.PA_DMSA_KEY_PACKAGE, v)
}

// GetKerbDMSAKeyPackage decodes the KerbDMSAKeyPackage carried by the value.
func (pa *PAData) GetKerbDMSAKeyPackage() (KerbDMSAKeyPackage, error) {
	var v KerbDMSAKeyPackage
	var err error
	err = getPAData(pa, patype.PA_DMSA_KEY_PACKAGE, &v)
	return v, err
}

// NewKerbADRestrictionEntry wraps KerbADRestriction in an authorization-data entry of its assigned type.
func NewKerbADRestrictionEntry(v KerbADRestrictionEntry) (AuthorizationDataEntry, error) {
	b, err := v.Marshal()
	return AuthorizationDataEntry{ADType: adtype.KerbAdRestrictionEntry, ADData: b}, err
}

// GetKerbADRestrictionEntry decodes the KerbADRestrictionEntry carried by the value.
func (a *AuthorizationDataEntry) GetKerbADRestrictionEntry() (KerbADRestrictionEntry, error) {
	var v KerbADRestrictionEntry
	var err error
	if a.ADType != adtype.KerbAdRestrictionEntry {
		return v, fmt.Errorf("authorization-data type mismatch: expected %d, got %d", adtype.KerbAdRestrictionEntry, a.ADType)
	}
	err = v.Unmarshal(a.ADData)
	return v, err
}

// NewKerbLocalEntry wraps KerbLocal in an authorization-data entry of its assigned type.
func NewKerbLocalEntry() AuthorizationDataEntry {
	return AuthorizationDataEntry{ADType: adtype.KerbLocal}
}

// IsKerbLocal reports whether the entry is a KERB-LOCAL authorization-data entry.
func (a *AuthorizationDataEntry) IsKerbLocal() bool {
	return a.ADType == adtype.KerbLocal && len(a.ADData) == 0
}

// NewADAuthDataAPOptionsEntry wraps ADAuthDataAPOptions in an authorization-data entry of its assigned type.
func NewADAuthDataAPOptionsEntry(options msflags.APOptions) (AuthorizationDataEntry, error) {
	v := ADAuthDataAPOptions(options)
	b, err := v.Marshal()
	return AuthorizationDataEntry{ADType: adtype.ADAuthDataAPOptions, ADData: b}, err
}

// GetADAuthDataAPOptions decodes the ADAuthDataAPOptions carried by the value.
func (a *AuthorizationDataEntry) GetADAuthDataAPOptions() (ADAuthDataAPOptions, error) {
	var v ADAuthDataAPOptions
	var err error
	if a.ADType != adtype.ADAuthDataAPOptions {
		return v, fmt.Errorf("authorization-data type mismatch: expected %d, got %d", adtype.ADAuthDataAPOptions, a.ADType)
	}
	err = v.Unmarshal(a.ADData)
	return v, err
}

// NewKerbDMSAKeyPackageEntry wraps KerbDMSAKeyPackage in an authorization-data entry of its assigned type.
func NewKerbDMSAKeyPackageEntry(v KerbDMSAKeyPackage) (AuthorizationDataEntry, error) {
	b, err := v.Marshal()
	return AuthorizationDataEntry{ADType: adtype.KerbDMSAKeyPackage, ADData: b}, err
}

// GetKerbDMSAKeyPackage decodes the KerbDMSAKeyPackage carried by the value.
func (a *AuthorizationDataEntry) GetKerbDMSAKeyPackage() (KerbDMSAKeyPackage, error) {
	var v KerbDMSAKeyPackage
	var err error
	if a.ADType != adtype.KerbDMSAKeyPackage {
		return v, fmt.Errorf("authorization-data type mismatch: expected %d, got %d", adtype.KerbDMSAKeyPackage, a.ADType)
	}
	err = v.Unmarshal(a.ADData)
	return v, err
}
