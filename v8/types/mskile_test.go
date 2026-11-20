package types

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
)

const (
	mskileExampleOrg = "EXAMPLE.ORG"
	mskileExampleCom = "EXAMPLE.COM"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMSKILEPADataWrappers(t *testing.T) {
	principal := NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	checksum := Checksum{CksumType: 1, Checksum: []byte("checksum")}

	checkPACOptionsAndForUserWrappers(t, principal, checksum)
	checkS4UAndSupportedEnctypeWrappers(t, principal, checksum)
	keyReply := checkKeyListWrappers(t)
	checkReferralAndSupersededWrappers(t, principal)
	checkDMSAKeyPackageWrappers(t, keyReply)
	checkWrongMSKILEPADataType(t)
}

func checkPACOptionsAndForUserWrappers(t *testing.T, principal PrincipalName, checksum Checksum) {
	t.Helper()
	pacOptions, err := NewPAPACOptionsPAData(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, ierr := pacOptions.GetPAPACOptions(); ierr != nil ||
		!IsFlagSet(&decoded.Options, 0) || !IsFlagSet(&decoded.Options, 3) {
		t.Fatalf("PAC options = %+v, %v", decoded, ierr)
	}
	if _, ierr := NewPAPACOptionsPAData(-1); ierr == nil {
		t.Fatal("negative PAC option accepted")
	}

	forUser := PAForUser{UserName: principal, UserRealm: mskileExampleOrg, Cksum: checksum, AuthPackage: "Kerberos"}
	forUserPA, err := NewPAForUserPAData(forUser)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, ierr := forUserPA.GetPAForUser(); ierr != nil || !decoded.UserName.Equal(principal) {
		t.Fatalf("PA-FOR-USER = %+v, %v", decoded, ierr)
	}
}

func checkS4UAndSupportedEnctypeWrappers(t *testing.T, principal PrincipalName, checksum Checksum) {
	t.Helper()
	userID := S4UUserID{
		Nonce:              7,
		CName:              principal,
		CRealm:             mskileExampleOrg,
		SubjectCertificate: nil,
		Options:            NewKrbFlags(),
	}
	s4u, err := NewPAS4UX509User(userID, checksum)
	if err != nil {
		t.Fatal(err)
	}
	s4uPA, err := NewPAS4UX509UserPAData(s4u)
	if err != nil {
		t.Fatal(err)
	}
	decodedS4U, err := s4uPA.GetPAS4UX509User()
	if err != nil {
		t.Fatal(err)
	}
	decodedUser, err := decodedS4U.GetUserID()
	if err != nil || decodedUser.Nonce != 7 {
		t.Fatalf("PA-S4U-X509-USER = %+v, %v", decodedUser, err)
	}

	supportedPA, err := NewPASupportedEncTypesPAData(PASupportedEncTypes(3))
	if err != nil {
		t.Fatal(err)
	}
	if decoded, ierr := supportedPA.GetPASupportedEncTypes(); ierr != nil || decoded != 3 {
		t.Fatalf("supported enctypes = %v, %v", decoded, ierr)
	}
}

func checkKeyListWrappers(t *testing.T) KerbKeyListRep {
	t.Helper()
	keyRequest := KerbKeyListReq{17, 18}
	keyRequestPA, err := NewKerbKeyListReqPAData(keyRequest)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, ierr := keyRequestPA.GetKerbKeyListReq(); ierr != nil || !reflect.DeepEqual(decoded, keyRequest) {
		t.Fatalf("key request = %+v, %v", decoded, ierr)
	}
	keyReply := KerbKeyListRep{{KeyType: 17, KeyValue: []byte("key")}}
	keyReplyPA, err := NewKerbKeyListRepPAData(keyReply)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, ierr := keyReplyPA.GetKerbKeyListRep(); ierr != nil || !reflect.DeepEqual(decoded, keyReply) {
		t.Fatalf("key reply = %+v, %v", decoded, ierr)
	}
	return keyReply
}

func checkReferralAndSupersededWrappers(t *testing.T, principal PrincipalName) {
	t.Helper()
	referral := PASvrReferralData{ReferredName: principal, ReferredRealm: "CHILD.EXAMPLE.ORG"}
	referralPA, err := NewPASvrReferralInfoPAData(referral)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, ierr := referralPA.GetPASvrReferralInfo(); ierr != nil || decoded.ReferredRealm != referral.ReferredRealm {
		t.Fatalf("referral = %+v, %v", decoded, ierr)
	}
	superseded := KerbSupersededByUser{Name: principal, Realm: mskileExampleOrg}
	supersededPA, err := NewKerbSupersededByUserPAData(superseded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, ierr := supersededPA.GetKerbSupersededByUser(); ierr != nil || !decoded.Name.Equal(principal) {
		t.Fatalf("superseded user = %+v, %v", decoded, ierr)
	}
}

func checkDMSAKeyPackageWrappers(t *testing.T, keyReply KerbKeyListRep) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	keyPackage := KerbDMSAKeyPackage{
		CurrentKeys:        keyReply,
		PreviousKeys:       keyReply,
		ExpirationInterval: now,
		FetchInterval:      now.Add(time.Hour),
	}
	keyPackagePA, err := NewKerbDMSAKeyPackagePAData(keyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, ierr := keyPackagePA.GetKerbDMSAKeyPackage(); ierr != nil || len(decoded.CurrentKeys) != 1 {
		t.Fatalf("dMSA package = %+v, %v", decoded, ierr)
	}
	keyPackageEntry, err := NewKerbDMSAKeyPackageEntry(keyPackage)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := keyPackageEntry.GetKerbDMSAKeyPackage(); err != nil || len(decoded.PreviousKeys) != 1 {
		t.Fatalf("dMSA entry = %+v, %v", decoded, err)
	}
}

func checkWrongMSKILEPADataType(t *testing.T) {
	t.Helper()
	wrong := PAData{PADataType: patype.PA_TGS_REQ, PADataValue: nil}
	getters := []func() error{
		func() error { _, err := wrong.GetPAPACOptions(); return err },
		func() error { _, err := wrong.GetPAForUser(); return err },
		func() error { _, err := wrong.GetPAS4UX509User(); return err },
		func() error { _, err := wrong.GetPASupportedEncTypes(); return err },
		func() error { _, err := wrong.GetKerbKeyListReq(); return err },
		func() error { _, err := wrong.GetKerbKeyListRep(); return err },
		func() error { _, err := wrong.GetPASvrReferralInfo(); return err },
		func() error { _, err := wrong.GetKerbSupersededByUser(); return err },
		func() error { _, err := wrong.GetKerbDMSAKeyPackage(); return err },
	}
	for index, get := range getters {
		if err := get(); err == nil {
			t.Fatalf("getter %d accepted wrong PA type", index)
		}
	}
}

func testPrincipal(name string) PrincipalName {
	return PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{name}}
}

func TestMSKILEExactVectors(t *testing.T) {
	checkMSKILEMarshalVectors(t)
	checkMSKILEExtendedErrorVector(t)
	checkMSKILERestrictionVector(t)
}

type mskileMarshalVector struct {
	name    string
	wantHex string
	marshal func() ([]byte, error)
}

func mskileMarshalVectors() []mskileMarshalVector {
	return []mskileMarshalVector{
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
				return (&KerbExtError{
					Status:   ntstatus.STATUS_ACCOUNT_DISABLED,
					Reserved: 0,
					Flags:    msflags.KerbExtErrorFlagStrongCredentials,
				}).Marshal()
			},
		},
		{
			name:    "supported enctypes",
			wantHex: testdata.MSKILEPASupportedEncTypes,
			marshal: func() ([]byte, error) {
				v := PASupportedEncTypes(msflags.SupportedEncTypeAES256CTSHMACSHA196 |
					msflags.SupportedEncTypeFAST | msflags.SupportedEncTypeClaims)
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
}

func checkMSKILEMarshalVectors(t *testing.T) {
	t.Helper()
	for _, tt := range mskileMarshalVectors() {
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
}

func checkMSKILEExtendedErrorVector(t *testing.T) {
	t.Helper()
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
}

func checkMSKILERestrictionVector(t *testing.T) {
	t.Helper()
	var restriction KerbADRestrictionEntry
	fixture := mustHex(t, testdata.MSKILEKerbADRestrictionEntry)
	if ierr := restriction.Unmarshal(fixture); ierr != nil {
		t.Fatal(ierr)
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
		ext, _ := (&KerbExtError{Status: ntstatus.STATUS_ACCOUNT_LOCKED_OUT, Reserved: 0, Flags: 1}).Marshal()
		want := KerbErrorData{DataType: int32(msflags.KERB_ERR_TYPE_EXTENDED), DataValue: ext}
		roundTripMSKILE(t, &want, new(KerbErrorData))
	})
	t.Run("restriction", func(t *testing.T) {
		var integrity LSAPTokenInfoIntegrity
		integrity.Flags = msflags.TokenInfoUACRestricted
		integrity.TokenIL = msflags.TokenILMedium
		copy(integrity.PerBootMachineID[:], bytes.Repeat([]byte{0x11}, 32))
		copy(integrity.CrossBootMachineID[:], bytes.Repeat([]byte{0x22}, 32))
		payload, _ := integrity.Marshal()
		want := KerbADRestrictionEntry{RestrictionType: msflags.KerbADRestrictionTypeTokenIntegrity, Restriction: payload}
		roundTripMSKILE(t, &want, new(KerbADRestrictionEntry))
	})
	t.Run("for user", func(t *testing.T) {
		want := PAForUser{UserName: principal, UserRealm: mskileExampleCom, Cksum: checksum, AuthPackage: "Kerberos"}
		roundTripMSKILE(t, &want, new(PAForUser))
	})
	t.Run("s4u x509 user", func(t *testing.T) {
		checkS4UX509UserRoundTrip(t, principal, checksum, options)
	})
	t.Run("key list reply", func(t *testing.T) {
		want := KerbKeyListRep{key}
		roundTripMSKILE(t, &want, &KerbKeyListRep{})
	})
	t.Run("server referral", func(t *testing.T) {
		want := PASvrReferralData{ReferredName: principal, ReferredRealm: mskileExampleCom}
		roundTripMSKILE(t, &want, new(PASvrReferralData))
	})
	t.Run("superseded user", func(t *testing.T) {
		want := KerbSupersededByUser{Name: principal, Realm: mskileExampleCom}
		roundTripMSKILE(t, &want, new(KerbSupersededByUser))
	})
	t.Run("dmsa key package", func(t *testing.T) {
		want := KerbDMSAKeyPackage{
			CurrentKeys:        KerbKeyListRep{key},
			PreviousKeys:       KerbKeyListRep{key},
			ExpirationInterval: now,
			FetchInterval:      now.Add(time.Hour),
		}
		roundTripMSKILE(t, &want, new(KerbDMSAKeyPackage))
	})
}

func checkS4UX509UserRoundTrip(t *testing.T, principal PrincipalName, checksum Checksum, options asn1.BitString) {
	t.Helper()
	userID := S4UUserID{
		Nonce:              ^uint32(0),
		CName:              principal,
		CRealm:             mskileExampleCom,
		SubjectCertificate: []byte{1, 2, 3},
		Options:            options,
	}
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
	if ierr := got.Unmarshal(b); ierr != nil {
		t.Fatal(ierr)
	}
	reencoded, err := got.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, reencoded) {
		t.Fatalf("round-trip mismatch\nwant %x\n got %x", b, reencoded)
	}
	for i := range len(b) {
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
		{"extended error", func() ([]byte, error) {
			return (&KerbExtError{Status: ntstatus.STATUS_PASSWORD_MUST_CHANGE, Reserved: 0, Flags: 0}).Marshal()
		}, new(KerbExtError).Unmarshal},
		{"token integrity", integrity.Marshal, new(LSAPTokenInfoIntegrity).Unmarshal},
		{"ap options", func() ([]byte, error) {
			v := ADAuthDataAPOptions(msflags.KERB_AP_OPTIONS_CBT)
			return v.Marshal()
		}, func(b []byte) error { var v ADAuthDataAPOptions; return v.Unmarshal(b) }},
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
			for i := range len(b) {
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

func TestMSKILEPADataGetterErrorResults(t *testing.T) {
	t.Parallel()

	t.Run("trailing data returns decoded prefix and error", func(t *testing.T) {
		pa, err := NewKerbPAPACRequestPAData(true)
		require.NoError(t, err)
		pa.PADataValue = append(pa.PADataValue, 0)

		request, err := pa.GetKerbPAPACRequest()
		require.EqualError(t, err, "trailing ASN.1 data: 1 bytes")
		require.True(t, request.IncludePAC)
	})

	t.Run("wrong type is rejected before decoding", func(t *testing.T) {
		pa, err := NewKerbPAPACRequestPAData(true)
		require.NoError(t, err)
		pa.PADataType = patype.PA_FOR_USER

		request, err := pa.GetKerbPAPACRequest()
		require.ErrorContains(t, err, "PAData type mismatch")
		require.False(t, request.IncludePAC)
	})

	t.Run("truncation retains the ASN.1 cause", func(t *testing.T) {
		pa := PAData{PADataType: patype.PA_SVR_REFERRAL_INFO, PADataValue: []byte{0x30, 0x01}}
		_, err := pa.GetPASvrReferralInfo()
		checkASN1ErrorContext[asn1.SyntaxError](t, err, "decode ASN.1 into *types.PASvrReferralData:")
	})
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
	if err := new(PAPACOptions).Unmarshal(pacBytes); err == nil {
		t.Fatal("short encoded PA-PAC-OPTIONS was accepted")
	}
	var user S4UUserID
	user.CRealm = mskileExampleCom
	user.Options = shortOptions
	if _, err := user.Marshal(); err == nil {
		t.Fatal("short S4U options were accepted")
	}
	var fastReq KrbFastReq
	fastReq.FastOptions = shortOptions
	if _, err := fastReq.Marshal(); err == nil {
		t.Fatal("short FAST options were accepted")
	}
}

func TestMSKILEExtendedErrorAndAuthorizationDataHelpers(t *testing.T) {
	checkMSKILEExtendedErrorData(t)
	checkMSKILEAuthorizationRestriction(t)
	checkMSKILELocalAndAPOptions(t)
}

func checkMSKILEExtendedErrorData(t *testing.T) {
	t.Helper()
	ext := KerbExtError{
		Status:   ntstatus.STATUS_ACCOUNT_DISABLED,
		Reserved: 0,
		Flags:    msflags.KerbExtErrorFlagStrongCredentials,
	}
	errorData, err := NewKerbExtErrorData(ext)
	if err != nil {
		t.Fatal(err)
	}
	gotExt, err := errorData.GetKerbExtError()
	if err != nil || gotExt != ext {
		t.Fatalf("extended error round trip: got %#v, %v", gotExt, err)
	}
	errorData.DataType = int32(msflags.KERB_AP_ERR_TYPE_SKEW_RECOVERY)
	if _, ierr := errorData.GetKerbExtError(); ierr == nil {
		t.Fatal("wrong KERB-ERROR-DATA type was accepted")
	}
}

func checkMSKILEAuthorizationRestriction(t *testing.T) {
	t.Helper()
	var integrity LSAPTokenInfoIntegrity
	integrity.TokenIL = msflags.TokenILMedium
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
	if _, ierr := gotRestriction.GetLSAPTokenInfoIntegrity(); ierr != nil {
		t.Fatal(ierr)
	}
	entry.ADType = adtype.KerbLocal
	if _, ierr := entry.GetKerbADRestrictionEntry(); ierr == nil {
		t.Fatal("wrong restriction authorization-data type was accepted")
	}
}

func checkMSKILELocalAndAPOptions(t *testing.T) {
	t.Helper()
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
	checkPAFXErrorHelpers(t)
	checkFASTRequestReplyAndChallenge(t)
}

func checkPAFXErrorHelpers(t *testing.T) {
	t.Helper()
	var nilFXError *PAFXError
	if err := nilFXError.Unmarshal([]byte{0}); err == nil {
		t.Fatal("nil PA-FX-ERROR receiver accepted input")
	}
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
	if _, ierr := pa.GetPAFXError(); ierr == nil {
		t.Fatal("wrong PA-FX-ERROR PA-DATA type was accepted")
	}
}

func checkFASTRequestReplyAndChallenge(t *testing.T) {
	t.Helper()
	var request PAFXFastRequest
	if ierr := request.Unmarshal(mustHex(t, testdata.MSKILEPAFXFastRequest)); ierr != nil {
		t.Fatal(ierr)
	}
	pa, err := NewPAFXFastRequestPAData(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, ierr := pa.GetPAFXFastRequest(); ierr != nil {
		t.Fatal(ierr)
	}

	var reply PAFXFastReply
	if ierr := reply.Unmarshal(mustHex(t, testdata.MSKILEPAFXFastReply)); ierr != nil {
		t.Fatal(ierr)
	}
	pa, err = NewPAFXFastReplyPAData(reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, ierr := pa.GetPAFXFastReply(); ierr != nil {
		t.Fatal(ierr)
	}

	var challenge PAEncryptedChallenge
	if ierr := challenge.Unmarshal(mustHex(t, testdata.MSKILEPAEncryptedChallenge)); ierr != nil {
		t.Fatal(ierr)
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
	encrypted := EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 0, Cipher: []byte{4, 5, 6}}
	request := PAFXFastRequest{ArmoredData: KrbFastArmoredReq{
		Armor:       KrbFastArmor{ArmorType: 1, ArmorValue: []byte{7, 8}},
		ReqChecksum: checksum,
		EncFastReq:  encrypted,
	}}
	roundTripMSKILE(t, &request, new(PAFXFastRequest))

	options := NewKrbFlags()
	fastReq := NewKrbFastReq(
		options,
		PADataSequence{{PADataType: patype.PA_FX_COOKIE, PADataValue: []byte("cookie")}},
		[]byte{0x30, 0x00},
	)
	roundTripMSKILE(t, &fastReq, new(KrbFastReq))

	reply := PAFXFastReply{ArmoredData: KrbFastArmoredRep{EncFastRep: encrypted}}
	roundTripMSKILE(t, &reply, new(PAFXFastReply))

	var response KrbFastResponse
	response.PAData = PADataSequence{}
	response.Nonce = ^uint32(0)
	roundTripMSKILE(t, &response, new(KrbFastResponse))
}

func TestMSKILEReferenceFixtures(t *testing.T) {
	var apOptions ADAuthDataAPOptions
	var supportedEncTypes PASupportedEncTypes
	tests := []struct {
		name  string
		hex   string
		codec mskileCodec
	}{
		{"KERB-PA-PAC-REQUEST", testdata.MSKILEKerbPAPACRequestTrue, new(KerbPAPACRequest)},
		{"PA-PAC-OPTIONS", testdata.MSKILEPAPACOptionsClaimsRBCD, new(PAPACOptions)},
		{"KERB-ERROR-DATA", testdata.MSKILEKerbErrorDataAccountDisabled, new(KerbErrorData)},
		{"KERB-EXT-ERROR", testdata.MSKILEKerbExtErrorAccountDisabled, new(KerbExtError)},
		{"KERB-AD-RESTRICTION-ENTRY", testdata.MSKILEKerbADRestrictionEntry, new(KerbADRestrictionEntry)},
		{"LSAP-TOKEN-INFO-INTEGRITY", testdata.MSKILELSAPTokenInfoIntegrity, new(LSAPTokenInfoIntegrity)},
		{"AD-AUTH-DATA-AP-OPTIONS", testdata.MSKILEADAuthDataAPOptionsCBT, &apOptions},
		{"PA-FOR-USER", testdata.MSKILEPAForUser, new(PAForUser)},
		{"S4UUserID", testdata.MSKILES4UUserID, new(S4UUserID)},
		{"PA-S4U-X509-USER", testdata.MSKILEPAS4UX509User, new(PAS4UX509User)},
		{"PA-SUPPORTED-ENCTYPES", testdata.MSKILEPASupportedEncTypes, &supportedEncTypes},
		{"KERB-KEY-LIST-REQ", testdata.MSKILEKerbKeyListReq, &KerbKeyListReq{}},
		{"KERB-KEY-LIST-REP", testdata.MSKILEKerbKeyListRep, &KerbKeyListRep{}},
		{"PA-SVR-REFERRAL-DATA", testdata.MSKILEPASvrReferralData, new(PASvrReferralData)},
		{"KERB-SUPERSEDED-BY-USER", testdata.MSKILEKerbSupersededByUser, new(KerbSupersededByUser)},
		{"KERB-DMSA-KEY-PACKAGE", testdata.MSKILEKerbDMSAKeyPackage, new(KerbDMSAKeyPackage)},
		{"KrbFastArmor", testdata.MSKILEKrbFastArmor, new(KrbFastArmor)},
		{"KrbFastArmoredReq", testdata.MSKILEKrbFastArmoredReq, new(KrbFastArmoredReq)},
		{"KrbFastReq", testdata.MSKILEKrbFastReq, new(KrbFastReq)},
		{"PA-FX-FAST-REQUEST", testdata.MSKILEPAFXFastRequest, new(PAFXFastRequest)},
		{"KrbFastArmoredRep", testdata.MSKILEKrbFastArmoredRep, new(KrbFastArmoredRep)},
		{"KrbFastResponse", testdata.MSKILEFastResponse, new(KrbFastResponse)},
		{"KrbFastFinished", testdata.MSKILEKrbFastFinished, new(KrbFastFinished)},
		{"PA-FX-FAST-REPLY", testdata.MSKILEPAFXFastReply, new(PAFXFastReply)},
		{"PA-ENCRYPTED-CHALLENGE", testdata.MSKILEPAEncryptedChallenge, new(PAEncryptedChallenge)},
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
			for i := range len(fixture) {
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
	f.Fuzz(func(_ *testing.T, b []byte) {
		decoders := []func([]byte) error{
			new(KerbPAPACRequest).Unmarshal,
			new(PAPACOptions).Unmarshal,
			new(KerbErrorData).Unmarshal,
			new(KerbExtError).Unmarshal,
			new(KerbADRestrictionEntry).Unmarshal,
			new(LSAPTokenInfoIntegrity).Unmarshal,
			func(b []byte) error { var v ADAuthDataAPOptions; return v.Unmarshal(b) },
			new(PAForUser).Unmarshal,
			new(S4UUserID).Unmarshal,
			new(PAS4UX509User).Unmarshal,
			func(b []byte) error { var v PASupportedEncTypes; return v.Unmarshal(b) },
			(&KerbKeyListReq{}).Unmarshal,
			(&KerbKeyListRep{}).Unmarshal,
			new(PASvrReferralData).Unmarshal,
			new(KerbSupersededByUser).Unmarshal,
			new(KerbDMSAKeyPackage).Unmarshal,
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
	f.Fuzz(func(_ *testing.T, b []byte) {
		decoders := []func([]byte) error{
			new(KrbFastArmor).Unmarshal,
			new(KrbFastArmoredReq).Unmarshal,
			new(KrbFastReq).Unmarshal,
			new(PAFXFastRequest).Unmarshal,
			new(KrbFastArmoredRep).Unmarshal,
			new(PAFXFastReply).Unmarshal,
			new(KrbFastFinished).Unmarshal,
			new(KrbFastResponse).Unmarshal,
			new(PAEncryptedChallenge).Unmarshal,
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
