package client

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const exchangeFixtureRealm = "EXAMPLE.ORG"

func phase5Keytab(t *testing.T, etypes ...int32) *keytab.Keytab {
	t.Helper()
	kt := keytab.New()
	principal := keytab.Principal{
		Realm:      exchangeFixtureRealm,
		Components: []string{"user"},
		NameType:   nametype.KRB_NT_PRINCIPAL,
	}
	for _, id := range etypes {
		et, err := crypto.GetEtype(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := kt.AddKey(
			principal,
			1,
			types.EncryptionKey{KeyType: id, KeyValue: make([]byte, et.GetKeyByteSize())},
			time.Now(),
		); err != nil {
			t.Fatal(err)
		}
	}
	return kt
}

func TestPKINITExchangeHelpers(t *testing.T) {
	data := types.PADataSequence{
		{PADataType: patype.PA_PK_AS_REQ, PADataValue: []byte("pkinit")},
		{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: []byte("timestamp")},
		{PADataType: patype.PA_PAC_REQUEST, PADataValue: []byte("keep")},
	}
	filtered := removePAData(data, patype.PA_PK_AS_REQ, patype.PA_ENC_TIMESTAMP)
	if len(filtered) != 1 || filtered[0].PADataType != patype.PA_PAC_REQUEST {
		t.Fatalf("filtered PA-DATA = %+v", filtered)
	}
	for _, code := range []int32{
		errorcode.KDC_ERR_PREAUTH_REQUIRED,
		errorcode.KDC_ERR_PREAUTH_FAILED,
		errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED,
		errorcode.KDC_ERR_PREAUTH_EXPIRED,
	} {
		if !isPKINITPreAuthError(code) {
			t.Fatalf("PKINIT pre-auth error %d was not recognized", code)
		}
	}
	if isPKINITPreAuthError(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN) {
		t.Fatal("unrelated KDC error was classified as PKINIT pre-auth")
	}

	if _, err := processPKINITReply(
		nil,
		nil,
		etypeID.AES256_CTS_HMAC_SHA1_96,
	); err == nil || !strings.Contains(err.Error(), "omitted") {
		t.Fatalf("missing reply error = %v", err)
	}
	duplicate := types.PADataSequence{
		{PADataType: patype.PA_PK_AS_REP, PADataValue: []byte{1}},
		{PADataType: patype.PA_PK_AS_REP, PADataValue: []byte{2}},
	}
	if _, err := processPKINITReply(
		nil,
		duplicate,
		etypeID.AES256_CTS_HMAC_SHA1_96,
	); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("duplicate reply error = %v", err)
	}
}

func TestFirstAvailablePreAuthKeyFallback(t *testing.T) {
	cl := NewWithPassword("user", exchangeFixtureRealm, "password", config.New())
	et, key, _, err := firstAvailablePreAuthKey(cl, []int32{-1, etypeID.AES256_CTS_HMAC_SHA1_96})
	if err != nil || et.GetETypeID() != etypeID.AES256_CTS_HMAC_SHA1_96 || len(key.KeyValue) == 0 {
		t.Fatalf("selected key = %v/%d bytes, %v", et, len(key.KeyValue), err)
	}
	if _, _, _, err := firstAvailablePreAuthKey(cl, nil); err == nil || !strings.Contains(
		err.Error(),
		"no encryption types",
	) {
		t.Fatalf("empty enctype error = %v", err)
	}
}

func TestASReqETypesRestrictedToKeytab(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17, 23}
	cl := NewWithKeytab("user", exchangeFixtureRealm, phase5Keytab(t, 17, 18), cfg)
	req, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []int32{18, 17}, req.ReqBody.EType)
}

func TestASExchangeTopLevelFailures(t *testing.T) {
	t.Run("configuration", func(t *testing.T) {
		client := NewWithPassword("user", exchangeFixtureRealm, "password", config.New())
		request, err := client.newASReq()
		require.NoError(t, err)
		if _, err := client.ASExchange(exchangeFixtureRealm, request, 0); err == nil {
			t.Fatal("unconfigured client performed AS exchange")
		}
	})

	newClient := func(options ...func(*Settings)) (*Client, messages.ASReq) {
		cfg := config.New()
		cfg.LibDefaults.DNSLookupKDC = true
		cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
		client := NewWithPassword("user", exchangeFixtureRealm, "password", cfg, options...)
		request, err := client.newASReq()
		require.NoError(t, err)
		return client, request
	}
	t.Run("transport", func(t *testing.T) {
		client, request := newClient()
		client.sendToKDCFunc = func([]byte, string) ([]byte, error) { return nil, errors.New("offline") }
		if _, err := client.ASExchange(exchangeFixtureRealm, request, 0); err == nil || !strings.Contains(
			err.Error(),
			"failed sending AS_REQ",
		) {
			t.Fatalf("transport error = %v", err)
		}
	})
	t.Run("referral limit", func(t *testing.T) {
		client, request := newClient()
		client.sendToKDCFunc = func([]byte, string) ([]byte, error) {
			return nil, messages.NewKRBError(request.ReqBody.CName, "OTHER.ORG", errorcode.KDC_ERR_WRONG_REALM, "referral")
		}
		if _, err := client.ASExchange(exchangeFixtureRealm, request, 6); err == nil || !strings.Contains(
			err.Error(),
			"maximum number",
		) {
			t.Fatalf("referral error = %v", err)
		}
	})
	t.Run("malformed reply", func(t *testing.T) {
		client, request := newClient()
		client.sendToKDCFunc = func([]byte, string) ([]byte, error) { return []byte("malformed"), nil }
		if _, err := client.ASExchange(exchangeFixtureRealm, request, 0); err == nil || !strings.Contains(
			err.Error(),
			"failed to process",
		) {
			t.Fatalf("malformed reply error = %v", err)
		}
	})
	t.Run("required FAST", func(t *testing.T) {
		client, request := newClient(RequireFAST(true))
		client.sendToKDCFunc = func([]byte, string) ([]byte, error) { return nil, errors.New("unexpected") }
		_, err := client.ASExchange(exchangeFixtureRealm, request, 0)
		require.ErrorContains(t, err, "FAST")
	})
}

func TestASReqETypesIntersectionError(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18}
	cl := NewWithKeytab("user", exchangeFixtureRealm, phase5Keytab(t, 17), cfg)
	_, err := cl.newASReq()
	assert.EqualError(t, err, "no supported encryption types (config file error?)")
}

func TestSetPADataETypeFromTktEnctypes(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{18, 17}
	cfg.LibDefaults.PreferredPreauthTypes = []int{2}
	cl := NewWithKeytab("user", exchangeFixtureRealm, phase5Keytab(t, 17), cfg, AssumePreAuthentication(true))
	req, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	if err := setPAData(cl, nil, &req); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, int32(17), cl.settings.preAuthEType)
	assert.Equal(t, patype.PA_ENC_TIMESTAMP, cl.settings.preAuthType)
	for _, pa := range req.PAData {
		if pa.PADataType != patype.PA_ENC_TIMESTAMP {
			continue
		}
		var encrypted types.PAEncTimestamp
		if err := encrypted.Unmarshal(pa.PADataValue); err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, int32(17), encrypted.EType)
		return
	}
	t.Fatal("PA-ENC-TIMESTAMP not found")
}

func TestSetPADataDoesNotRecordTimestampWithoutPreAuth(t *testing.T) {
	cl := NewWithPassword("user", exchangeFixtureRealm, "password", config.New())
	req, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	if err := setPAData(cl, nil, &req); err != nil {
		t.Fatal(err)
	}
	assert.Zero(t, cl.settings.preAuthType)
	assert.False(t, req.PAData.Contains(patype.PA_ENC_TIMESTAMP))
}

func TestPKINITPreAuthHelpers(t *testing.T) {
	data := types.PADataSequence{
		{PADataType: patype.PA_PK_AS_REQ, PADataValue: []byte("pkinit")},
		{PADataType: patype.PA_TGS_REQ, PADataValue: []byte("keep")},
		{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: []byte("timestamp")},
	}
	filtered := removePAData(data, patype.PA_PK_AS_REQ, patype.PA_ENC_TIMESTAMP)
	if len(filtered) != 1 || filtered[0].PADataType != patype.PA_TGS_REQ {
		t.Fatalf("filtered PA-DATA = %+v", filtered)
	}

	for _, code := range []int32{
		errorcode.KDC_ERR_PREAUTH_REQUIRED,
		errorcode.KDC_ERR_PREAUTH_FAILED,
		errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED,
		errorcode.KDC_ERR_PREAUTH_EXPIRED,
	} {
		if !isPKINITPreAuthError(code) {
			t.Fatalf("code %d was not classified as PKINIT preauth", code)
		}
	}
	if isPKINITPreAuthError(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN) {
		t.Fatal("unrelated KDC error was classified as PKINIT preauth")
	}

	if _, err := processPKINITReply(
		nil,
		nil,
		etypeID.AES128_CTS_HMAC_SHA1_96,
	); err == nil || !strings.Contains(err.Error(), "omitted") {
		t.Fatalf("missing reply error = %v", err)
	}
	duplicate := types.PADataSequence{
		{PADataType: patype.PA_PK_AS_REP, PADataValue: []byte("one")},
		{PADataType: patype.PA_PK_AS_REP, PADataValue: []byte("two")},
	}
	if _, err := processPKINITReply(
		nil,
		duplicate,
		etypeID.AES128_CTS_HMAC_SHA1_96,
	); err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("duplicate reply error = %v", err)
	}
}

func TestFirstAvailablePreAuthKey(t *testing.T) {
	client := NewWithKeytab("user", exchangeFixtureRealm, phase5Keytab(t, etypeID.AES128_CTS_HMAC_SHA1_96), config.New())
	et, key, kvno, err := firstAvailablePreAuthKey(client, []int32{9999, etypeID.AES128_CTS_HMAC_SHA1_96})
	if err != nil {
		t.Fatal(err)
	}
	if et.GetETypeID() != etypeID.AES128_CTS_HMAC_SHA1_96 || key.KeyType != etypeID.AES128_CTS_HMAC_SHA1_96 || kvno != 1 {
		t.Fatalf("selected key = etype %d, key %d, kvno %d", et.GetETypeID(), key.KeyType, kvno)
	}
	if _, _, _, err := firstAvailablePreAuthKey(client, nil); err == nil || !strings.Contains(
		err.Error(),
		"no encryption types",
	) {
		t.Fatalf("empty request error = %v", err)
	}
	if _, _, _, err := firstAvailablePreAuthKey(client, []int32{9999}); err == nil {
		t.Fatal("unsupported encryption type unexpectedly selected")
	}
}

func TestPreAuthETypeUsesFirstRequestedKDCOffer(t *testing.T) {
	var emptyPrincipal types.PrincipalName

	entries := types.ETypeInfo2{
		{Salt: "", S2KParams: nil, EType: etypeID.AES256_CTS_HMAC_SHA1_96},
		{Salt: "", S2KParams: nil, EType: etypeID.AES128_CTS_HMAC_SHA1_96},
	}
	info, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	methodData, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
	if err != nil {
		t.Fatal(err)
	}
	et, err := preAuthEType(&messages.KRBError{
		PVNO:      0,
		MsgType:   0,
		CTime:     time.Time{},
		Cusec:     0,
		STime:     time.Time{},
		Susec:     0,
		ErrorCode: 0,
		CRealm:    "",
		CName:     emptyPrincipal,
		Realm:     "",
		SName:     emptyPrincipal,
		EText:     "",
		EData:     methodData,
	}, []int32{etypeID.AES128_CTS_HMAC_SHA1_96})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.AES128_CTS_HMAC_SHA1_96, et.GetETypeID())
}

func TestPreAuthETypeAcceptsETypeInfoOnly(t *testing.T) {
	var emptyPrincipal types.PrincipalName

	entries := types.ETypeInfo{{EType: etypeID.DES3_CBC_SHA1_KD, Salt: []byte("legacy-salt")}}
	info, err := asn1.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	methodData, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO, PADataValue: info}})
	if err != nil {
		t.Fatal(err)
	}
	et, err := preAuthEType(&messages.KRBError{
		PVNO:      0,
		MsgType:   0,
		CTime:     time.Time{},
		Cusec:     0,
		STime:     time.Time{},
		Susec:     0,
		ErrorCode: 0,
		CRealm:    "",
		CName:     emptyPrincipal,
		Realm:     "",
		SName:     emptyPrincipal,
		EText:     "",
		EData:     methodData,
	}, []int32{etypeID.DES3_CBC_SHA1_KD})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, etypeID.DES3_CBC_SHA1_KD, et.GetETypeID())
}

func TestASExchangePasswordReplyUsesPreAuthSalt(t *testing.T) {
	const salt = "non-default-kdc-salt"
	entries := types.ETypeInfo2{{S2KParams: nil, EType: etypeID.AES128_CTS_HMAC_SHA1_96, Salt: salt}}
	info, err := asn1.Marshal(entries)
	require.NoError(t, err)
	methodData, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
	require.NoError(t, err)
	et, err := crypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
	require.NoError(t, err)
	replyKey, err := et.StringToKey("password", salt, et.GetDefaultStringToKeyParams())
	require.NoError(t, err)

	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	cl := NewWithPassword("user", exchangeFixtureRealm, "password", cfg, DisablePAReqEncPARep(true))
	request, err := cl.newASReq()
	require.NoError(t, err)
	calls := 0
	cl.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		calls++
		if calls == 1 {
			preAuthError := messages.NewKRBError(
				request.ReqBody.CName,
				request.ReqBody.Realm,
				errorcode.KDC_ERR_PREAUTH_REQUIRED,
				"pre-authentication required",
			)
			preAuthError.EData = methodData
			return nil, preAuthError
		}
		var retried messages.ASReq
		require.NoError(t, retried.Unmarshal(requestBytes))
		partBytes := marshalPasswordASReplyPart(t, &retried.ReqBody)
		reply := messages.ASRep{KDCRepFields: testKDCReplyFields(&retried.ReqBody, msgtype.KRB_AS_REP)}
		reply.EncPart, err = crypto.GetEncryptedData(
			partBytes,
			types.EncryptionKey{KeyType: et.GetETypeID(), KeyValue: replyKey},
			keyusage.AS_REP_ENCPART,
			0,
		)
		require.NoError(t, err)
		return reply.Marshal()
	}

	if _, err := cl.ASExchange(exchangeFixtureRealm, request, 0); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 2, calls)
}

func TestLoginWithOptionsCachesServiceASReply(t *testing.T) {
	var (
		emptyEncryptedData types.EncryptedData
		emptyReplyPart     messages.EncKDCRepPart
	)

	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	cl := NewWithPassword("user", exchangeFixtureRealm, "password", cfg,
		AssumePreAuthentication(true), DisablePAReqEncPARep(true))
	service := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/server.example.org")
	calls := 0
	cl.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		calls++
		var request messages.ASReq
		require.NoError(t, request.Unmarshal(requestBytes))
		if !request.ReqBody.SName.Equal(service) || !request.PAData.Contains(patype.PA_ENC_TIMESTAMP) {
			t.Fatalf("AS request service/pre-auth = %+v/%+v", request.ReqBody.SName, request.PAData)
		}
		replyKey, _, err := crypto.GetKeyFromPassword("password", request.ReqBody.CName, request.ReqBody.Realm,
			etypeID.AES128_CTS_HMAC_SHA1_96, nil)
		require.NoError(t, err)
		partBytes := marshalPasswordASReplyPart(t, &request.ReqBody)
		reply := messages.ASRep{KDCRepFields: messages.KDCRepFields{
			PAData:           nil,
			EncPart:          emptyEncryptedData,
			DecryptedEncPart: emptyReplyPart,
			PVNO:             iana.PVNO, MsgType: msgtype.KRB_AS_REP, CRealm: request.ReqBody.Realm,
			CName: request.ReqBody.CName, Ticket: s4uTestTicket(request.ReqBody.Realm, service.PrincipalNameString()),
		}}
		reply.EncPart, err = crypto.GetEncryptedData(partBytes, replyKey, keyusage.AS_REP_ENCPART, 0)
		require.NoError(t, err)
		return reply.Marshal()
	}
	if err := cl.LoginWithOptions(messages.ASReqOptions{
		Lifetime:         nil,
		RenewLifetime:    nil,
		Forwardable:      nil,
		Proxiable:        nil,
		Canonicalize:     nil,
		IncludePAC:       nil,
		Addresses:        nil,
		Enterprise:       nil,
		StartTime:        nil,
		ServicePrincipal: &service,
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("KDC calls = %d, want 1", calls)
	}
	if ticket, key, ok := cl.GetCachedTicket(
		service.PrincipalNameString(),
	); !ok || !ticket.SName.Equal(service) || string(key.KeyValue) != "session-key-1234" {
		t.Fatalf("cached service ticket = %+v/%x/%v", ticket.SName, key.KeyValue, ok)
	}
}

func marshalPasswordASReplyPart(t *testing.T, body *messages.KDCReqBody) []byte {
	t.Helper()
	now := time.Now().UTC()
	part := messages.EncKDCRepPart{
		Key:           types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("session-key-1234")},
		LastReqs:      nil,
		Nonce:         body.Nonce,
		KeyExpiration: time.Time{},
		Flags:         types.NewKrbFlags(),
		AuthTime:      now,
		StartTime:     now,
		EndTime:       now.Add(time.Hour),
		RenewTill:     time.Time{},
		SRealm:        body.Realm,
		SName:         body.SName,
		CAddr:         nil,
		EncPAData:     nil,
	}
	data, err := part.Marshal()
	require.NoError(t, err)
	return data
}

func TestClientCCacheExportRoundTrip(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	original := new(credentials.CCache)
	if ierr := original.Unmarshal(data); ierr != nil {
		t.Fatal(ierr)
	}
	cl, err := NewFromCCache(original, config.New())
	if err != nil {
		t.Fatal(err)
	}
	cl.settings.preAuthType = patype.PA_ENC_TIMESTAMP
	exported, err := cl.CCache()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, exported.GetEntries(), len(original.GetEntries()))
	_, found := exported.GetConfig("fast_avail", "krbtgt/TEST.GOKRB5@TEST.GOKRB5")
	assert.False(t, found)
	paType, found := exported.GetConfig("pa_type", "krbtgt/TEST.GOKRB5@TEST.GOKRB5")
	assert.True(t, found)
	assert.Equal(t, "2", paType)
	wantOffset, wantOffsetPresent := original.KDCTimeOffset()
	gotOffset, gotOffsetPresent := exported.KDCTimeOffset()
	assert.Equal(t, wantOffsetPresent, gotOffsetPresent)
	assert.Equal(t, wantOffset, gotOffset)

	encoded, err := exported.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	reparsed := new(credentials.CCache)
	if ierr := reparsed.Unmarshal(encoded); ierr != nil {
		t.Fatal(ierr)
	}
	cl2, err := NewFromCCache(reparsed, config.New())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, patype.PA_ENC_TIMESTAMP, cl2.settings.preAuthType)
	exportedAgain, err := cl2.CCache()
	if err != nil {
		t.Fatal(err)
	}
	encodedAgain, err := exportedAgain.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, encoded, encodedAgain)
}

// TestNewFromCCacheMatchesTGTRealmCaseInsensitively guards against a regression where a
// ccache's DefaultPrincipal.Realm has different casing than the realm embedded in the
// cached TGT's service name (e.g. a custom identity entered in a different case, or a
// cross-realm referral). Previously this caused NewFromCCache to silently skip adding a
// session, so a later Renew() would fail with "TGT session not found for realm ..." even
// though a valid TGT was present in the cache.
func TestNewFromCCacheMatchesTGTRealmCaseInsensitively(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	original := new(credentials.CCache)
	if ierr := original.Unmarshal(data); ierr != nil {
		t.Fatal(ierr)
	}
	// Lower-case the default principal's realm while the TGT credential entry keeps its
	// original (upper-case) realm, simulating the casing mismatch.
	realm := original.DefaultPrincipal.Realm
	original.DefaultPrincipal.Realm = strings.ToLower(realm)
	original.DefaultPrincipal.PrincipalName.NameString = append(
		[]string(nil),
		original.DefaultPrincipal.PrincipalName.NameString...,
	)

	cl, err := NewFromCCache(original, config.New())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cl.sessions.get(realm); !ok {
		t.Fatalf("expected a TGT session to be registered for realm %s", realm)
	}
	// Renew() must get past the session lookup (it will still fail attempting the
	// network exchange against an unreachable KDC, which is expected in this test).
	if err := cl.Renew(); err == nil || strings.Contains(err.Error(), "TGT session not found") {
		t.Fatalf("Renew() = %v, did not expect a session-not-found error", err)
	}
}

func TestClientCCacheExportAssociatesPATypeWithInitialService(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	original := new(credentials.CCache)
	if ierr := original.Unmarshal(data); ierr != nil {
		t.Fatal(ierr)
	}
	credential := original.GetEntries()[0]
	var ticket messages.Ticket
	if ierr := ticket.Unmarshal(credential.Ticket); ierr != nil {
		t.Fatal(ierr)
	}
	ticket.SName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.example.org")
	ticket.Realm = exchangeFixtureRealm
	cl := NewWithPassword("user", exchangeFixtureRealm, "password", config.New())
	cl.cache.addEntryWithDetails(ticket, credential.AuthTime, credential.StartTime, credential.EndTime,
		credential.RenewTill, credential.Key, credential.TicketFlags, credential.Addresses,
		credential.AuthData, credential.IsSKey, credential.SecondTicket)
	cl.settings.preAuthType = patype.PA_ENC_TIMESTAMP

	exported, err := cl.CCache()
	if err != nil {
		t.Fatal(err)
	}
	paType, found := exported.GetConfig("pa_type", "HTTP/host.example.org@EXAMPLE.ORG")
	assert.True(t, found)
	assert.Equal(t, "2", paType)
	_, found = exported.GetConfig("pa_type", "krbtgt/EXAMPLE.ORG@EXAMPLE.ORG")
	assert.False(t, found)

	reloaded, err := NewFromCCache(exported, config.New())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := reloaded.CCache()
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, roundTrip.GetEntries(), 1)
	paType, found = roundTrip.GetConfig("pa_type", "HTTP/host.example.org@EXAMPLE.ORG")
	assert.True(t, found)
	assert.Equal(t, "2", paType)
}

func asErrorAt(response messages.KRBError, at time.Time) messages.KRBError {
	response.STime = at.Truncate(time.Second)
	response.Susec = at.Nanosecond() / int(time.Microsecond)
	return response
}

func TestClockSkewRetry(t *testing.T) {
	var emptyPrincipal types.PrincipalName

	synctest.Test(t, func(t *testing.T) {
		cfg := config.New()
		cfg.LibDefaults.DNSLookupKDC = true
		cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
		kt := phase5Keytab(t, etypeID.AES128_CTS_HMAC_SHA1_96)
		cl := NewWithKeytab(
			"user",
			exchangeFixtureRealm,
			kt,
			cfg,
			AssumePreAuthentication(true),
		)
		const skew = 10*time.Minute + 123456*time.Microsecond
		serverTime := clientNow().UTC().Add(skew)
		calls := 0
		var retriedRequest []byte
		cl.sendToKDCFunc = func(request []byte, _ string) ([]byte, error) {
			calls++
			if calls == 1 {
				response := messages.NewKRBError(
					emptyPrincipal, exchangeFixtureRealm, errorcode.KRB_AP_ERR_SKEW, "skew",
				)
				return nil, asErrorAt(response, serverTime)
			}
			retriedRequest = append([]byte(nil), request...)
			return nil, messages.NewKRBError(
				emptyPrincipal,
				exchangeFixtureRealm,
				errorcode.KDC_ERR_CLIENT_REVOKED,
				"stop",
			)
		}
		req, err := cl.newASReq()
		require.NoError(t, err)
		_, err = cl.ASExchange(exchangeFixtureRealm, req, 0)
		var terminal messages.KRBError
		require.ErrorAs(t, err, &terminal)
		assert.Equal(t, errorcode.KDC_ERR_CLIENT_REVOKED, terminal.ErrorCode)
		require.Equal(t, 2, calls)
		assert.Equal(t, skew, cl.KDCTimeOffset())
		assert.Equal(t, serverTime, decodeASReqTimestamp(t, cl, retriedRequest))
	})
}

func decodeASReqTimestamp(t *testing.T, cl *Client, request []byte) time.Time {
	t.Helper()
	var req messages.ASReq
	require.NoError(t, req.Unmarshal(request))
	for _, pa := range req.PAData {
		if pa.PADataType != patype.PA_ENC_TIMESTAMP {
			continue
		}
		var encrypted types.PAEncTimestamp
		require.NoError(t, encrypted.Unmarshal(pa.PADataValue))
		et, err := crypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
		require.NoError(t, err)
		key, _, err := cl.Key(et, 0, nil)
		require.NoError(t, err)
		plain, err := crypto.DecryptMessage(encrypted.Cipher, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP)
		require.NoError(t, err)
		var timestamp types.PAEncTSEnc
		require.NoError(t, timestamp.Unmarshal(plain))
		return timestamp.PATimestamp.Add(time.Duration(timestamp.PAUSec) * time.Microsecond).UTC()
	}
	t.Fatal("retried PA-ENC-TIMESTAMP not found")
	return time.Time{}
}

func TestPreAuthRequiredLearnsKDCTimeOffset(t *testing.T) {
	var emptyPrincipal types.PrincipalName

	synctest.Test(t, func(t *testing.T) {
		cfg := config.New()
		cfg.LibDefaults.DNSLookupKDC = true
		cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
		cl := NewWithKeytab("user", exchangeFixtureRealm, phase5Keytab(t, etypeID.AES128_CTS_HMAC_SHA1_96), cfg)
		const skew = -time.Hour
		serverTime := clientNow().UTC().Add(skew)
		entries := types.ETypeInfo2{{Salt: "", S2KParams: nil, EType: etypeID.AES128_CTS_HMAC_SHA1_96}}
		info, err := asn1.Marshal(entries)
		require.NoError(t, err)
		methodData, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
		require.NoError(t, err)
		cl.sendToKDCFunc = func(_ []byte, _ string) ([]byte, error) {
			response := messages.NewKRBError(
				emptyPrincipal, exchangeFixtureRealm, errorcode.KDC_ERR_PREAUTH_REQUIRED, "pre-authentication required",
			)
			response.EData = methodData
			return nil, asErrorAt(response, serverTime)
		}
		req, err := cl.newASReq()
		require.NoError(t, err)
		_, err = cl.ASExchange(exchangeFixtureRealm, req, 0)
		var terminal messages.KRBError
		require.ErrorAs(t, err, &terminal)
		assert.Equal(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, terminal.ErrorCode)
		assert.Equal(t, skew, cl.KDCTimeOffset())
	})
}

func TestClockSkewRetryDisabled(t *testing.T) {
	var emptyPrincipal types.PrincipalName

	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.KDCTimeSync = 0
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	cl := NewWithKeytab(
		"user",
		exchangeFixtureRealm,
		phase5Keytab(t, etypeID.AES128_CTS_HMAC_SHA1_96),
		cfg,
		AssumePreAuthentication(true),
	)
	calls := 0
	cl.sendToKDCFunc = func(_ []byte, _ string) ([]byte, error) {
		calls++
		return nil, messages.NewKRBError(emptyPrincipal, exchangeFixtureRealm, errorcode.KRB_AP_ERR_SKEW, "skew")
	}
	req, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	_, err = cl.ASExchange(exchangeFixtureRealm, req, 0)
	assert.Error(t, err)
	assert.Equal(t, 1, calls)
	assert.Zero(t, cl.KDCTimeOffset())
}
