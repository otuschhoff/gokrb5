package service

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestVerifyAPREQ(t *testing.T) {
	t.Parallel()
	creds := newAPTestCredentials(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		panic(err)
	}

	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(creds.CName(), creds.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(t, creds),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	badRequest := APReq
	badRequest.Ticket.EncPart.Cipher = nil
	result, err := VerifyAPREQWithResult(&badRequest, s)
	assert.Nil(t, result.Credentials)
	assert.ErrorContains(t, err, "verify service AP-REQ:")
	_, hasCause := errors.AsType[krberror.Krberror](err)
	assert.True(t, hasCause, "expected the verification error cause")

	result, err = VerifyAPREQWithResult(&APReq, NewSettings(kt, ClientAddress(h), RequireHostAddr(true)))
	assert.Nil(t, result.Credentials)
	wireErr := requireServiceWireError(t, err, errorcode.KRB_AP_ERR_BADADDR)
	assert.Equal(t, APReq.Ticket.Realm, wireErr.Realm)

	ok, _, err := VerifyAPREQ(&APReq, s)
	if !ok || err != nil {
		t.Fatalf("Validation of AP_REQ failed when it should not have: %v", err)
	}
}

func TestVerifyAPREQRejectsMissingInput(t *testing.T) {
	t.Parallel()

	require.NotPanics(t, func() {
		result, err := VerifyAPREQWithResult(nil, NewSettings(nil))
		assert.Nil(t, result.Credentials)
		assert.ErrorContains(t, err, "service AP-REQ is nil")
	})
}

func TestVerifyAPREQPreservesServiceMismatchProtocolError(t *testing.T) {
	t.Parallel()

	var request messages.APReq
	request.Ticket.SName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/unconfigured")
	request.Ticket.Realm = testdata.TEST_REALM
	result, err := VerifyAPREQWithResult(&request, NewSettings(nil))
	assert.Nil(t, result.Credentials)
	wireErr := requireServiceWireError(t, err, errorcode.KRB_AP_ERR_NOT_US)

	encoded, err := wireErr.Marshal()
	require.NoError(t, err)
	var decoded messages.KRBError
	require.NoError(t, decoded.Unmarshal(encoded))
	assert.Equal(t, wireErr.ErrorCode, decoded.ErrorCode)
	assert.Equal(t, request.Ticket.Realm, decoded.Realm)
	assert.Equal(t, request.Ticket.SName, decoded.SName)
}

func TestVerifyAPREQWithResultWithholdsCredentialsOnDelegationFailure(t *testing.T) {
	t.Parallel()

	const realm = "TEST.GOKRB5"
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "delegation-regression")
	sname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/host.test.gokrb5")
	rawKeytab, err := hex.DecodeString(testdata.HTTP_KEYTAB)
	require.NoError(t, err)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(rawKeytab))
	now := time.Now().UTC()
	ticket, key, err := messages.NewTicket(
		cname, realm, sname, realm, types.NewKrbFlags(), kt,
		18, 1, now, now, now.Add(time.Hour), now.Add(time.Hour),
	)
	require.NoError(t, err)
	authenticator, err := types.NewAuthenticator(realm, cname)
	require.NoError(t, err)
	checksum := gssapi.NewAuthenticatorChecksum(nil, gssapi.ContextFlagDeleg)
	checksum.DelegationOption = 1
	checksum.Deleg = []byte{0x76} // Incomplete KRB-CRED in the local test fixture.
	rawChecksum, err := checksum.Marshal()
	require.NoError(t, err)
	authenticator.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: rawChecksum}
	request, err := messages.NewAPReq(ticket, key, authenticator)
	require.NoError(t, err)

	result, err := VerifyAPREQWithResult(&request, NewSettings(kt))
	assert.ErrorContains(t, err, "invalid delegated KRB_CRED")
	if result.Credentials != nil {
		t.Error("failed verification published authenticated credentials")
	}
}

func TestVerifyAPREQIgnoresKerbLocalAndRestrictionEntry(t *testing.T) {
	creds := newAPTestCredentials(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, err := hex.DecodeString(testdata.HTTP_KEYTAB)
	if err != nil {
		t.Fatal(err)
	}
	kt := keytab.New()
	if ierr := kt.Unmarshal(b); ierr != nil {
		t.Fatal(ierr)
	}
	now := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(
		creds.CName(), creds.Domain(), sname, "TEST.GOKRB5",
		types.NewKrbFlags(), kt, 18, 1, now, now, now.Add(24*time.Hour), now.Add(48*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	restriction, err := types.NewKerbADRestrictionEntryForToken(types.LSAPTokenInfoIntegrity{
		Flags:   msflags.TokenInfoUACRestricted,
		TokenIL: msflags.TokenILMedium,
	})
	if err != nil {
		t.Fatal(err)
	}
	restrictionEntry, err := types.NewKerbADRestrictionEntry(restriction)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := newTestAuthenticator(t, creds)
	authenticator.AuthorizationData = types.AuthorizationData{
		types.NewKerbLocalEntry(),
		restrictionEntry,
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	hostAddress, err := types.GetHostAddress("127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	ok, _, err := VerifyAPREQ(&apReq, NewSettings(kt, ClientAddress(hostAddress)))
	if err != nil || !ok {
		t.Fatalf("VerifyAPREQ rejected Microsoft authorization data: %v", err)
	}
}

func TestVerifyAPREQWithPrincipalOverride(t *testing.T) {
	t.Parallel()
	creds := newAPTestCredentials(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		panic(err)
	}

	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(creds.CName(), creds.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	apReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(t, creds),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h), KeytabPrincipal("foo"))
	ok, _, err := VerifyAPREQ(&apReq, s)
	if ok || err == nil {
		t.Fatalf("Validation of AP_REQ should have failed")
	}
	if !strings.Contains(err.Error(), "Looking for \"foo\" realm") {
		t.Fatalf("Looking for wrong entity: %s", err.Error())
	}
}

func TestVerifyAPREQ_KRB_AP_ERR_BADMATCH(t *testing.T) {
	t.Parallel()
	creds := newAPTestCredentials(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		panic(err)
	}

	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(creds.CName(), creds.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(t, creds)
	a.CName = types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"BADMATCH"},
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	var krbErr messages.KRBError
	if errors.As(err, &krbErr) {
		assert.Equal(t, errorcode.KRB_AP_ERR_BADMATCH, krbErr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_LargeClockSkew(t *testing.T) {
	t.Parallel()
	creds := newAPTestCredentials(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		panic(err)
	}

	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(creds.CName(), creds.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(t, creds)
	a.CTime = a.CTime.Add(time.Duration(-10) * time.Minute)
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	var krbErr messages.KRBError
	if errors.As(err, &krbErr) {
		assert.Equal(t, errorcode.KRB_AP_ERR_SKEW, krbErr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_Replay(t *testing.T) {
	t.Parallel()
	creds := newAPTestCredentials(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		panic(err)
	}

	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(creds.CName(), creds.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(t, creds),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if !ok || err != nil {
		t.Fatalf("Validation of AP_REQ failed when it should not have: %v", err)
	}
	// Replay
	ok, _, err = VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	wireErr := requireServiceWireError(t, err, errorcode.KRB_AP_ERR_REPEAT)
	assert.Equal(t, APReq.Ticket.Realm, wireErr.Realm)
}

func requireServiceWireError(t *testing.T, err error, code int32) messages.KRBError {
	t.Helper()
	wireErr, ok := errors.AsType[messages.KRBError](err)
	require.True(t, ok, "expected a KRB-ERROR, got %v", err)
	assert.IsType(t, wireErr, err)
	assert.Equal(t, code, wireErr.ErrorCode)
	return wireErr
}

func TestVerifyAPREQ_FutureTicket(t *testing.T) {
	t.Parallel()
	creds := newAPTestCredentials(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		panic(err)
	}

	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(creds.CName(), creds.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st.Add(time.Duration(60)*time.Minute),
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(t, creds)
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	var krbErr messages.KRBError
	if errors.As(err, &krbErr) {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_NYV, krbErr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_InvalidTicket(t *testing.T) {
	t.Parallel()
	creds := newAPTestCredentials(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		panic(err)
	}

	st := time.Now().UTC()
	f := types.NewKrbFlags()
	types.SetFlag(&f, flags.Invalid)
	tkt, sessionKey, err := messages.NewTicket(creds.CName(), creds.Domain(),
		sname, "TEST.GOKRB5",
		f,
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		newTestAuthenticator(t, creds),
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	var krbErr messages.KRBError
	if errors.As(err, &krbErr) {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_NYV, krbErr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestVerifyAPREQ_ExpiredTicket(t *testing.T) {
	t.Parallel()
	creds := newAPTestCredentials(t)
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		panic(err)
	}

	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(creds.CName(), creds.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(-30)*time.Minute),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(t, creds)
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		a,
	)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	s := NewSettings(kt, ClientAddress(h))
	ok, _, err := VerifyAPREQ(&APReq, s)
	if ok || err == nil {
		t.Fatal("Validation of AP_REQ passed when it should not have")
	}
	var krbErr messages.KRBError
	if errors.As(err, &krbErr) {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_EXPIRED, krbErr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestExtendedProtectionPolicy(t *testing.T) {
	t.Parallel()
	bindings := &gssapi.ChannelBindings{ApplicationData: []byte("tls-server-end-point:test")}
	matching := gssapi.NewAuthenticatorChecksum(bindings, gssapi.ContextFlagInteg)
	matchingBytes, err := matching.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	missing := types.Checksum{}
	present := types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: matchingBytes}
	mismatchChecksum := gssapi.NewAuthenticatorChecksum(&gssapi.ChannelBindings{ApplicationData: []byte("different")})
	mismatchBytes, err := mismatchChecksum.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	mismatch := types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: mismatchBytes}

	tests := []struct {
		name    string
		policy  ExtendedProtectionPolicy
		binding *gssapi.ChannelBindings
		check   types.Checksum
		wantErr bool
	}{
		{name: "disabled missing", policy: ExtendedProtectionDisabled, check: missing},
		{name: "disabled mismatch", policy: ExtendedProtectionDisabled, binding: bindings, check: mismatch},
		{name: "allowed missing", policy: ExtendedProtectionAllowed, binding: bindings, check: missing},
		{name: "allowed matching", policy: ExtendedProtectionAllowed, binding: bindings, check: present},
		{name: "allowed mismatch", policy: ExtendedProtectionAllowed, binding: bindings, check: mismatch, wantErr: true},
		{name: "required missing", policy: ExtendedProtectionRequired, binding: bindings, check: missing, wantErr: true},
		{name: "required matching", policy: ExtendedProtectionRequired, binding: bindings, check: present},
		{name: "required mismatch", policy: ExtendedProtectionRequired, binding: bindings, check: mismatch, wantErr: true},
		{name: "required configuration", policy: ExtendedProtectionRequired, check: present, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := verifyAuthenticatorChecksum(test.check, NewSettings(nil, ExtendedProtection(test.policy), ChannelBindings(test.binding)))
			assert.Equal(t, test.wantErr, err != nil)
		})
	}
}

func TestExtendedProtectionAllowedEnforcesAdvertisedCBT(t *testing.T) {
	bindings := &gssapi.ChannelBindings{ApplicationData: []byte("tls-server-end-point:expected")}
	checksum := gssapi.NewAuthenticatorChecksum(nil)
	checksumBytes, err := checksum.Marshal()
	assert.NoError(t, err)
	raw := types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksumBytes}

	_, _, err = verifyAuthenticatorChecksumWithCBT(raw, NewSettings(nil,
		ExtendedProtection(ExtendedProtectionAllowed), ChannelBindings(bindings)), false)
	assert.NoError(t, err)
	_, _, err = verifyAuthenticatorChecksumWithCBT(raw, NewSettings(nil,
		ExtendedProtection(ExtendedProtectionAllowed), ChannelBindings(bindings)), true)
	assert.Error(t, err)
}

func TestServicePrincipalAllowed(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.HTTP_KEYTAB)
	if err != nil {
		t.Fatal(err)
	}
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		panic(err)
	}
	sname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/host.test.gokrb5")

	assert.True(t, servicePrincipalAllowed(sname, "test.gokrb5", NewSettings(kt)))
	assert.True(t, servicePrincipalAllowed(sname, "TEST.GOKRB5", NewSettings(kt, ServicePrincipals("HTTP/host.test.gokrb5"))))
	assert.False(t, servicePrincipalAllowed(sname, "OTHER.REALM", NewSettings(kt)))
	assert.False(t, servicePrincipalAllowed(sname, "TEST.GOKRB5", NewSettings(kt, ServicePrincipals("HTTP/other.test.gokrb5@TEST.GOKRB5"))))
}

func TestExtractDelegatedCredentials(t *testing.T) {
	t.Parallel()
	var ticket messages.Ticket
	ticketBytes, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	if err != nil {
		t.Fatal(err)
	}
	if ierr := ticket.Unmarshal(ticketBytes); ierr != nil {
		t.Fatal(ierr)
	}
	key := types.EncryptionKey{KeyType: 18, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
	info := messages.KrbCredInfo{
		Key: key, PRealm: testdata.TEST_REALM,
		PName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser"),
		Flags: types.NewKrbFlags(), SRealm: ticket.Realm, SName: ticket.SName,
	}
	delegated, err := messages.NewKRBCred([]messages.Ticket{ticket}, []messages.KrbCredInfo{info}, key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := delegated.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	got, err := extractDelegatedCredentials(gssapi.AuthenticatorChecksum{
		Flags: gssapi.ContextFlagDeleg, DelegationOption: 1, Deleg: wire,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if assert.Len(t, got, 1) {
		assert.Equal(t, info.SName, got[0].Server.PrincipalName)
		assert.Equal(t, key, got[0].Key)
	}
}

func newTestAuthenticator(t *testing.T, creds *credentials.Credentials) types.Authenticator {
	t.Helper()
	auth, err := types.NewAuthenticator(creds.Domain(), creds.CName())
	require.NoError(t, err)
	require.NoError(t, auth.GenerateSeqNumberAndSubKey(18, 32))
	return auth
}

func newAPTestCredentials(t *testing.T) *credentials.Credentials {
	t.Helper()
	creds := credentials.New(t.Name(), testdata.TEST_REALM)
	// Parallel and repeated tests share the replay cache even when clock ticks coincide.
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, t.Name()+"-"+creds.SessionID())
	creds.SetCName(cname)
	return creds
}
