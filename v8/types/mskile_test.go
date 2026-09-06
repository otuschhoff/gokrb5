package types

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/adtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/msflags"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/ntstatus"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testPrincipal(name string) PrincipalName {
	return PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{name}}
}

func TestMSKILEExactVectors(t *testing.T) {
	tests := []struct {
		name    string
		wantHex string
		marshal func() ([]byte, error)
	}{
		{
			name:    "pac request true",
			wantHex: testdata.MSKILEKerbPAPACRequestTrue,
			marshal: func() ([]byte, error) { return (&KerbPAPACRequest{IncludePAC: true}).Marshal() },
		},
		{
			name:    "pac options claims and rbcd",
			wantHex: testdata.MSKILEPAPACOptionsClaimsRBCD,
			marshal: func() ([]byte, error) {
				pa, err := NewPAPACOptionsPAData(flags.PACOptionClaims, flags.PACOptionResourceBasedConstrainedDelegation)
				return pa.PADataValue, err
			},
		},
		{
			name:    "extended error",
			wantHex: "720000c00000000001000000",
			marshal: func() ([]byte, error) {
				return (&KerbExtError{Status: ntstatus.STATUS_ACCOUNT_DISABLED, Flags: msflags.KerbExtErrorFlagStrongCredentials}).Marshal()
			},
		},
		{
			name:    "supported enctypes",
			wantHex: testdata.MSKILEPASupportedEncTypes,
			marshal: func() ([]byte, error) {
				v := PASupportedEncTypes(msflags.SupportedEncTypeAES256CTSHMACSHA196 | msflags.SupportedEncTypeFAST | msflags.SupportedEncTypeClaims)
				return v.Marshal()
			},
		},
		{
			name:    "auth data ap options",
			wantHex: "00c00000",
			marshal: func() ([]byte, error) {
				v := ADAuthDataAPOptions(msflags.KERB_AP_OPTIONS_CBT | msflags.KERB_AP_OPTIONS_UNVERIFIED_TARGET_NAME)
				return v.Marshal()
			},
		},
		{
			name:    "key list request",
			wantHex: testdata.MSKILEKerbKeyListReq,
			marshal: func() ([]byte, error) {
				v := KerbKeyListReq{18, 17, 23}
				return v.Marshal()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.marshal()
			if err != nil {
				t.Fatal(err)
			}
			if want := mustHex(t, tt.wantHex); !bytes.Equal(want, got) {
				t.Fatalf("encoding mismatch\nwant %x\n got %x", want, got)
			}
		})
	}

	extended := KerbErrorData{
		DataType:  int32(msflags.KERB_ERR_TYPE_EXTENDED),
		DataValue: mustHex(t, "720000c00000000001000000"),
	}
	encoded, err := extended.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, testdata.MSKILEKerbErrorDataAccountDisabled); !bytes.Equal(want, encoded) {
		t.Fatalf("KERB-ERROR-DATA mismatch\nwant %x\n got %x", want, encoded)
	}

	var restriction KerbADRestrictionEntry
	fixture := mustHex(t, testdata.MSKILEKerbADRestrictionEntry)
	if err := restriction.Unmarshal(fixture); err != nil {
		t.Fatal(err)
	}
	reencoded, err := restriction.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixture, reencoded) {
		t.Fatalf("restriction fixture mismatch\nwant %x\n got %x", fixture, reencoded)
	}
}

func TestMSKILEASN1RoundTrips(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 34, 56, 0, time.UTC)
	principal := testPrincipal("alice")
	checksum := Checksum{CksumType: 16, Checksum: []byte{1, 2, 3, 4}}
	key := EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{0x5a}, 32)}
	options := NewKrbFlags()
	SetFlag(&options, flags.PACOptionBranchAware)

	t.Run("error data", func(t *testing.T) {
		ext, _ := (&KerbExtError{Status: ntstatus.STATUS_ACCOUNT_LOCKED_OUT, Flags: 1}).Marshal()
		want := KerbErrorData{DataType: int32(msflags.KERB_ERR_TYPE_EXTENDED), DataValue: ext}
		roundTripMSKILE(t, &want, &KerbErrorData{})
	})
	t.Run("restriction", func(t *testing.T) {
		integrity := LSAPTokenInfoIntegrity{Flags: msflags.TokenInfoUACRestricted, TokenIL: msflags.TokenILMedium}
		copy(integrity.PerBootMachineID[:], bytes.Repeat([]byte{0x11}, 32))
		copy(integrity.CrossBootMachineID[:], bytes.Repeat([]byte{0x22}, 32))
		payload, _ := integrity.Marshal()
		want := KerbADRestrictionEntry{RestrictionType: msflags.KerbADRestrictionTypeTokenIntegrity, Restriction: payload}
		roundTripMSKILE(t, &want, &KerbADRestrictionEntry{})
	})
	t.Run("for user", func(t *testing.T) {
		want := PAForUser{UserName: principal, UserRealm: "EXAMPLE.COM", Cksum: checksum, AuthPackage: "Kerberos"}
		roundTripMSKILE(t, &want, &PAForUser{})
	})
	t.Run("s4u x509 user", func(t *testing.T) {
		userID := S4UUserID{Nonce: ^uint32(0), CName: principal, CRealm: "EXAMPLE.COM", SubjectCertificate: []byte{1, 2, 3}, Options: options}
		want, err := NewPAS4UX509User(userID, checksum)
		if err != nil {
			t.Fatal(err)
		}
		var got PAS4UX509User
		roundTripMSKILE(t, &want, &got)
		decoded, err := got.GetUserID()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(userID, decoded) {
			t.Fatalf("S4U user mismatch\nwant %#v\n got %#v", userID, decoded)
		}
	})
	t.Run("key list reply", func(t *testing.T) {
		want := KerbKeyListRep{key}
		roundTripMSKILE(t, &want, &KerbKeyListRep{})
	})
	t.Run("server referral", func(t *testing.T) {
		want := PASvrReferralData{ReferredName: principal, ReferredRealm: "EXAMPLE.COM"}
		roundTripMSKILE(t, &want, &PASvrReferralData{})
	})
	t.Run("superseded user", func(t *testing.T) {
		want := KerbSupersededByUser{Name: principal, Realm: "EXAMPLE.COM"}
		roundTripMSKILE(t, &want, &KerbSupersededByUser{})
	})
	t.Run("dmsa key package", func(t *testing.T) {
		want := KerbDMSAKeyPackage{CurrentKeys: KerbKeyListRep{key}, PreviousKeys: KerbKeyListRep{key}, ExpirationInterval: now, FetchInterval: now.Add(time.Hour)}
		roundTripMSKILE(t, &want, &KerbDMSAKeyPackage{})
	})
}

type mskileCodec interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}

func roundTripMSKILE(t *testing.T, want, got mskileCodec) []byte {
	t.Helper()
	b, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	reencoded, err := got.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, reencoded) {
		t.Fatalf("round-trip mismatch\nwant %x\n got %x", b, reencoded)
	}
	for i := 0; i < len(b); i++ {
		if err := got.Unmarshal(b[:i]); err == nil {
			t.Fatalf("accepted truncation at %d of %d bytes", i, len(b))
		}
	}
	return b
}

func TestMSKILEBinaryLengthsAndTruncations(t *testing.T) {
	var integrity LSAPTokenInfoIntegrity
	copy(integrity.PerBootMachineID[:], bytes.Repeat([]byte{0x11}, 32))
	copy(integrity.CrossBootMachineID[:], bytes.Repeat([]byte{0x22}, 32))

	vectors := []struct {
		name      string
		marshal   func() ([]byte, error)
		unmarshal func([]byte) error
	}{
		{"extended error", func() ([]byte, error) { return (&KerbExtError{Status: ntstatus.STATUS_PASSWORD_MUST_CHANGE}).Marshal() }, (&KerbExtError{}).Unmarshal},
		{"token integrity", integrity.Marshal, (&LSAPTokenInfoIntegrity{}).Unmarshal},
		{"ap options", func() ([]byte, error) { v := ADAuthDataAPOptions(msflags.KERB_AP_OPTIONS_CBT); return v.Marshal() }, func(b []byte) error { var v ADAuthDataAPOptions; return v.Unmarshal(b) }},
		{"supported enctypes", func() ([]byte, error) {
			v := PASupportedEncTypes(msflags.SupportedEncTypeAES256CTSHMACSHA196)
			return v.Marshal()
		}, func(b []byte) error { var v PASupportedEncTypes; return v.Unmarshal(b) }},
	}
	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.marshal()
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < len(b); i++ {
				if err := tt.unmarshal(b[:i]); err == nil {
					t.Fatalf("accepted truncation at %d of %d bytes", i, len(b))
				}
			}
			if err := tt.unmarshal(append(append([]byte(nil), b...), 0)); err == nil {
				t.Fatal("accepted trailing byte")
			}
		})
	}
}

func TestMSKILEPADataConstructors(t *testing.T) {
	pac, err := NewKerbPAPACRequestPAData(true)
	if err != nil {
		t.Fatal(err)
	}
	if pac.PADataType != patype.PA_PAC_REQUEST {
		t.Fatalf("unexpected PA-DATA type %d", pac.PADataType)
	}
	decoded, err := pac.GetKerbPAPACRequest()
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.IncludePAC {
		t.Fatal("include-pac was not preserved")
	}
	pac.PADataType = patype.PA_FOR_USER
	if _, err := pac.GetKerbPAPACRequest(); err == nil {
		t.Fatal("wrong PA-DATA type was accepted")
	}

	if _, err := NewPAPACOptionsPAData(32); err == nil {
		t.Fatal("out-of-range PAC option was accepted")
	}
}

func TestMSKILESemanticValidation(t *testing.T) {
	shortOptions := asn1.BitString{Bytes: []byte{0x80}, BitLength: 8}
	if _, err := (&PAPACOptions{Options: shortOptions}).Marshal(); err == nil {
		t.Fatal("short PA-PAC-OPTIONS was accepted")
	}
	pacBytes, err := asn1.Marshal(PAPACOptions{Options: shortOptions})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&PAPACOptions{}).Unmarshal(pacBytes); err == nil {
		t.Fatal("short encoded PA-PAC-OPTIONS was accepted")
	}
	if _, err := (&S4UUserID{CRealm: "EXAMPLE.COM", Options: shortOptions}).Marshal(); err == nil {
		t.Fatal("short S4U options were accepted")
	}
	if _, err := (&KrbFastReq{FastOptions: shortOptions}).Marshal(); err == nil {
		t.Fatal("short FAST options were accepted")
	}
}

func TestMSKILEExtendedErrorAndAuthorizationDataHelpers(t *testing.T) {
	ext := KerbExtError{Status: ntstatus.STATUS_ACCOUNT_DISABLED, Flags: msflags.KerbExtErrorFlagStrongCredentials}
	errorData, err := NewKerbExtErrorData(ext)
	if err != nil {
		t.Fatal(err)
	}
	gotExt, err := errorData.GetKerbExtError()
	if err != nil || gotExt != ext {
		t.Fatalf("extended error round trip: got %#v, %v", gotExt, err)
	}
	errorData.DataType = int32(msflags.KERB_AP_ERR_TYPE_SKEW_RECOVERY)
	if _, err := errorData.GetKerbExtError(); err == nil {
		t.Fatal("wrong KERB-ERROR-DATA type was accepted")
	}

	integrity := LSAPTokenInfoIntegrity{TokenIL: msflags.TokenILMedium}
	restriction, err := NewKerbADRestrictionEntryForToken(integrity)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := NewKerbADRestrictionEntry(restriction)
	if err != nil {
		t.Fatal(err)
	}
	gotRestriction, err := entry.GetKerbADRestrictionEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gotRestriction.GetLSAPTokenInfoIntegrity(); err != nil {
		t.Fatal(err)
	}
	entry.ADType = adtype.KerbLocal
	if _, err := entry.GetKerbADRestrictionEntry(); err == nil {
		t.Fatal("wrong restriction authorization-data type was accepted")
	}

	local := NewKerbLocalEntry()
	if !local.IsKerbLocal() {
		t.Fatal("KERB-LOCAL entry was not recognized")
	}
	local.ADData = []byte{0}
	if local.IsKerbLocal() {
		t.Fatal("non-empty KERB-LOCAL entry was accepted")
	}

	apEntry, err := NewADAuthDataAPOptionsEntry(msflags.KERB_AP_OPTIONS_CBT)
	if err != nil {
		t.Fatal(err)
	}
	gotOptions, err := apEntry.GetADAuthDataAPOptions()
	if err != nil || msflags.APOptions(gotOptions) != msflags.KERB_AP_OPTIONS_CBT {
		t.Fatalf("AP options round trip: got %#x, %v", gotOptions, err)
	}
	apEntry.ADType = adtype.KerbLocal
	if _, err := apEntry.GetADAuthDataAPOptions(); err == nil {
		t.Fatal("wrong AP-options authorization-data type was accepted")
	}
}

func TestFASTPADataHelpers(t *testing.T) {
	fxError := PAFXError(mustHex(t, testdata.MSKILEPAFXError))
	pa, err := NewPAFXErrorPAData(fxError)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pa.GetPAFXError()
	if err != nil || !bytes.Equal(got, fxError) {
		t.Fatalf("PA-FX-ERROR round trip: got %x, %v", got, err)
	}
	pa.PADataType = patype.PA_FX_FAST
	if _, err := pa.GetPAFXError(); err == nil {
		t.Fatal("wrong PA-FX-ERROR PA-DATA type was accepted")
	}

	request := PAFXFastRequest{}
	if err := request.Unmarshal(mustHex(t, testdata.MSKILEPAFXFastRequest)); err != nil {
		t.Fatal(err)
	}
	pa, err = NewPAFXFastRequestPAData(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pa.GetPAFXFastRequest(); err != nil {
		t.Fatal(err)
	}

	reply := PAFXFastReply{}
	if err := reply.Unmarshal(mustHex(t, testdata.MSKILEPAFXFastReply)); err != nil {
		t.Fatal(err)
	}
	pa, err = NewPAFXFastReplyPAData(reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pa.GetPAFXFastReply(); err != nil {
		t.Fatal(err)
	}

	challenge := PAEncryptedChallenge{}
	if err := challenge.Unmarshal(mustHex(t, testdata.MSKILEPAEncryptedChallenge)); err != nil {
		t.Fatal(err)
	}
	pa, err = NewPAEncryptedChallengePAData(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pa.GetPAEncryptedChallenge(); err != nil {
		t.Fatal(err)
	}
}

func TestFASTRoundTrips(t *testing.T) {
	checksum := Checksum{CksumType: 16, Checksum: []byte{1, 2, 3}}
	encrypted := EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, Cipher: []byte{4, 5, 6}}
	request := PAFXFastRequest{ArmoredData: KrbFastArmoredReq{
		Armor:       KrbFastArmor{ArmorType: 1, ArmorValue: []byte{7, 8}},
		ReqChecksum: checksum,
		EncFastReq:  encrypted,
	}}
	roundTripMSKILE(t, &request, &PAFXFastRequest{})

	options := NewKrbFlags()
	fastReq := NewKrbFastReq(options, PADataSequence{{PADataType: patype.PA_FX_COOKIE, PADataValue: []byte("cookie")}}, []byte{0x30, 0x00})
	roundTripMSKILE(t, &fastReq, &KrbFastReq{})

	reply := PAFXFastReply{ArmoredData: KrbFastArmoredRep{EncFastRep: encrypted}}
	roundTripMSKILE(t, &reply, &PAFXFastReply{})

	response := KrbFastResponse{PAData: PADataSequence{}, Nonce: ^uint32(0)}
	roundTripMSKILE(t, &response, &KrbFastResponse{})
}

func TestMSKILEReferenceFixtures(t *testing.T) {
	var apOptions ADAuthDataAPOptions
	var supportedEncTypes PASupportedEncTypes
	tests := []struct {
		name  string
		hex   string
		codec mskileCodec
	}{
		{"KERB-PA-PAC-REQUEST", testdata.MSKILEKerbPAPACRequestTrue, &KerbPAPACRequest{}},
		{"PA-PAC-OPTIONS", testdata.MSKILEPAPACOptionsClaimsRBCD, &PAPACOptions{}},
		{"KERB-ERROR-DATA", testdata.MSKILEKerbErrorDataAccountDisabled, &KerbErrorData{}},
		{"KERB-EXT-ERROR", testdata.MSKILEKerbExtErrorAccountDisabled, &KerbExtError{}},
		{"KERB-AD-RESTRICTION-ENTRY", testdata.MSKILEKerbADRestrictionEntry, &KerbADRestrictionEntry{}},
		{"LSAP-TOKEN-INFO-INTEGRITY", testdata.MSKILELSAPTokenInfoIntegrity, &LSAPTokenInfoIntegrity{}},
		{"AD-AUTH-DATA-AP-OPTIONS", testdata.MSKILEADAuthDataAPOptionsCBT, &apOptions},
		{"PA-FOR-USER", testdata.MSKILEPAForUser, &PAForUser{}},
		{"S4UUserID", testdata.MSKILES4UUserID, &S4UUserID{}},
		{"PA-S4U-X509-USER", testdata.MSKILEPAS4UX509User, &PAS4UX509User{}},
		{"PA-SUPPORTED-ENCTYPES", testdata.MSKILEPASupportedEncTypes, &supportedEncTypes},
		{"KERB-KEY-LIST-REQ", testdata.MSKILEKerbKeyListReq, &KerbKeyListReq{}},
		{"KERB-KEY-LIST-REP", testdata.MSKILEKerbKeyListRep, &KerbKeyListRep{}},
		{"PA-SVR-REFERRAL-DATA", testdata.MSKILEPASvrReferralData, &PASvrReferralData{}},
		{"KERB-SUPERSEDED-BY-USER", testdata.MSKILEKerbSupersededByUser, &KerbSupersededByUser{}},
		{"KERB-DMSA-KEY-PACKAGE", testdata.MSKILEKerbDMSAKeyPackage, &KerbDMSAKeyPackage{}},
		{"KrbFastArmor", testdata.MSKILEKrbFastArmor, &KrbFastArmor{}},
		{"KrbFastArmoredReq", testdata.MSKILEKrbFastArmoredReq, &KrbFastArmoredReq{}},
		{"KrbFastReq", testdata.MSKILEKrbFastReq, &KrbFastReq{}},
		{"PA-FX-FAST-REQUEST", testdata.MSKILEPAFXFastRequest, &PAFXFastRequest{}},
		{"KrbFastArmoredRep", testdata.MSKILEKrbFastArmoredRep, &KrbFastArmoredRep{}},
		{"KrbFastResponse", testdata.MSKILEFastResponse, &KrbFastResponse{}},
		{"KrbFastFinished", testdata.MSKILEKrbFastFinished, &KrbFastFinished{}},
		{"PA-FX-FAST-REPLY", testdata.MSKILEPAFXFastReply, &PAFXFastReply{}},
		{"PA-ENCRYPTED-CHALLENGE", testdata.MSKILEPAEncryptedChallenge, &PAEncryptedChallenge{}},
		{"PA-FX-ERROR", testdata.MSKILEPAFXError, &PAFXError{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := mustHex(t, tt.hex)
			if err := tt.codec.Unmarshal(fixture); err != nil {
				t.Fatal(err)
			}
			got, err := tt.codec.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(fixture, got) {
				t.Fatalf("fixture round-trip mismatch\nwant %x\n got %x", fixture, got)
			}
			for i := 0; i < len(fixture); i++ {
				if err := tt.codec.Unmarshal(fixture[:i]); err == nil {
					t.Fatalf("accepted truncation at %d of %d bytes", i, len(fixture))
				}
			}
		})
	}
}

func FuzzMSKILEUnmarshal(f *testing.F) {
	seeds := []string{
		testdata.MSKILEKerbPAPACRequestTrue,
		testdata.MSKILEPAPACOptionsClaimsRBCD,
		testdata.MSKILEKerbErrorDataAccountDisabled,
		testdata.MSKILEKerbExtErrorAccountDisabled,
		testdata.MSKILEKerbADRestrictionEntry,
		testdata.MSKILELSAPTokenInfoIntegrity,
		testdata.MSKILEADAuthDataAPOptionsCBT,
		testdata.MSKILEPAForUser,
		testdata.MSKILES4UUserID,
		testdata.MSKILEPAS4UX509User,
		testdata.MSKILEPASupportedEncTypes,
		testdata.MSKILEKerbKeyListReq,
		testdata.MSKILEKerbKeyListRep,
		testdata.MSKILEPASvrReferralData,
		testdata.MSKILEKerbSupersededByUser,
		testdata.MSKILEKerbDMSAKeyPackage,
	}
	for _, seed := range seeds {
		f.Add(mustHexForFuzz(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		decoders := []func([]byte) error{
			(&KerbPAPACRequest{}).Unmarshal,
			(&PAPACOptions{}).Unmarshal,
			(&KerbErrorData{}).Unmarshal,
			(&KerbExtError{}).Unmarshal,
			(&KerbADRestrictionEntry{}).Unmarshal,
			(&LSAPTokenInfoIntegrity{}).Unmarshal,
			func(b []byte) error { var v ADAuthDataAPOptions; return v.Unmarshal(b) },
			(&PAForUser{}).Unmarshal,
			(&S4UUserID{}).Unmarshal,
			(&PAS4UX509User{}).Unmarshal,
			func(b []byte) error { var v PASupportedEncTypes; return v.Unmarshal(b) },
			(&KerbKeyListReq{}).Unmarshal,
			(&KerbKeyListRep{}).Unmarshal,
			(&PASvrReferralData{}).Unmarshal,
			(&KerbSupersededByUser{}).Unmarshal,
			(&KerbDMSAKeyPackage{}).Unmarshal,
		}
		for _, decode := range decoders {
			_ = decode(b)
		}
	})
}

func FuzzFASTUnmarshal(f *testing.F) {
	seeds := []string{
		testdata.MSKILEKrbFastArmor,
		testdata.MSKILEKrbFastArmoredReq,
		testdata.MSKILEKrbFastReq,
		testdata.MSKILEPAFXFastRequest,
		testdata.MSKILEKrbFastArmoredRep,
		testdata.MSKILEFastResponse,
		testdata.MSKILEKrbFastFinished,
		testdata.MSKILEPAFXFastReply,
		testdata.MSKILEPAEncryptedChallenge,
		testdata.MSKILEPAFXError,
	}
	for _, seed := range seeds {
		f.Add(mustHexForFuzz(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		decoders := []func([]byte) error{
			(&KrbFastArmor{}).Unmarshal,
			(&KrbFastArmoredReq{}).Unmarshal,
			(&KrbFastReq{}).Unmarshal,
			(&PAFXFastRequest{}).Unmarshal,
			(&KrbFastArmoredRep{}).Unmarshal,
			(&PAFXFastReply{}).Unmarshal,
			(&KrbFastFinished{}).Unmarshal,
			(&KrbFastResponse{}).Unmarshal,
			(&PAEncryptedChallenge{}).Unmarshal,
			(&PAFXError{}).Unmarshal,
		}
		for _, decode := range decoders {
			_ = decode(b)
		}
	})
}

func mustHexForFuzz(value string) []byte {
	b, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return b
}
