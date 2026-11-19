package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math"
	"math/big"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func asPKINITClient(t *testing.T, assume, freshness bool) (*Client, messages.ASReq) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{17}
	cl := NewWithPassword("user", "EXAMPLE.ORG", "password", cfg,
		PKINITIdentity(&pkinit.Identity{Certificate: cert, Signer: key}),
		AssumePreAuthentication(assume), PKINITRequireFreshness(freshness))
	cl.settings.pkinitOptions.ValidateIdentity = func(*pkinit.Identity, types.PrincipalName, string) error { return nil }
	request, err := cl.newASReq()
	require.NoError(t, err)
	return cl, request
}

func asPKINITError(t *testing.T, code int32, token string) messages.KRBError {
	t.Helper()
	response := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", code, "scripted")
	response.STime = time.Time{}
	response.Susec = 0
	if token != "" {
		var err error
		response.EData, err = asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_AS_FRESHNESS, PADataValue: []byte(token)}})
		require.NoError(t, err)
	}
	return response
}

func asPKINITAuthPack(t *testing.T, request messages.ASReq) pkinit.AuthPack {
	t.Helper()
	for _, pa := range request.PAData {
		if pa.PADataType != patype.PA_PK_AS_REQ {
			continue
		}
		var encoded pkinit.PAPKAsReq
		require.NoError(t, encoded.Unmarshal(pa.PADataValue))
		signed, err := pkinit.VerifySignedData(encoded.SignedAuthPack, pkinit.OIDPKINITAuthData)
		require.NoError(t, err)
		var pack pkinit.AuthPack
		require.NoError(t, pack.Unmarshal(signed.Content))
		require.Equal(t, int64(request.ReqBody.Nonce), pack.PKAuthenticator.Nonce)
		return pack
	}
	t.Fatal("missing PA-PK-AS-REQ")
	return pkinit.AuthPack{}
}

type asPKINITStep struct {
	code  int32
	token string
}

func runASPKINITScript(t *testing.T, cl *Client, request messages.ASReq, steps []asPKINITStep) ([]messages.ASReq, error) {
	t.Helper()
	var requests []messages.ASReq
	cl.sendToKDCFunc = func(b []byte, realm string) ([]byte, error) {
		require.Equal(t, "EXAMPLE.ORG", realm)
		var req messages.ASReq
		require.NoError(t, req.Unmarshal(b))
		require.Less(t, len(requests), len(steps), "unexpected retry")
		step := steps[len(requests)]
		requests = append(requests, req)
		return nil, asPKINITError(t, step.code, step.token)
	}
	_, err := cl.ASExchange("EXAMPLE.ORG", request, 0)
	require.Len(t, requests, len(steps))
	_, published := cl.takePKINITReplyKey("EXAMPLE.ORG")
	require.False(t, published, "failed exchange published a reply key")
	return requests, err
}

func TestASExchangePKINITInitiation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		assume    bool
		freshness bool
		signed    bool
	}{
		{name: "discovery"},
		{name: "preemptive", assume: true, signed: true},
		{name: "required freshness defers signing", assume: true, freshness: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl, req := asPKINITClient(t, tc.assume, tc.freshness)
			requests, err := runASPKINITScript(t, cl, req, []asPKINITStep{{code: errorcode.KDC_ERR_CLIENT_REVOKED}})
			require.ErrorContains(t, err, "kerberos error response from KDC")
			require.Equal(t, tc.signed, requests[0].PAData.Contains(patype.PA_PK_AS_REQ))
			require.Equal(t, !tc.signed, requests[0].PAData.Contains(patype.PA_AS_FRESHNESS))
			require.False(t, requests[0].PAData.Contains(patype.PA_ENC_TIMESTAMP))
			require.Empty(t, cl.settings.pkinitOptions.KDCCertificate.Realm, "options must be copied")
		})
	}
}

func TestASExchangePKINITFreshnessBudgets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		freshness bool
		steps     []asPKINITStep
		want      string
	}{
		{name: "required missing", freshness: true, steps: []asPKINITStep{{code: errorcode.KDC_ERR_PREAUTH_REQUIRED}}, want: "did not provide required PKINIT freshness token"},
		{name: "expired missing", steps: []asPKINITStep{{code: errorcode.KDC_ERR_PREAUTH_EXPIRED}}, want: "PKINIT freshness retry failed"},
		{name: "expired once", steps: []asPKINITStep{{code: errorcode.KDC_ERR_PREAUTH_EXPIRED, token: "one"}, {code: errorcode.KDC_ERR_PREAUTH_EXPIRED, token: "two"}}, want: "PKINIT freshness retry failed"},
		{name: "five rounds", steps: []asPKINITStep{
			{code: errorcode.KDC_ERR_PREAUTH_REQUIRED, token: "one"},
			{code: errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, token: "two"},
			{code: errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, token: "three"},
			{code: errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, token: "four"},
			{code: errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, token: "five"},
			{code: errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, token: "six"},
		}, want: "maximum PKINIT pre-authentication rounds exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl, req := asPKINITClient(t, false, tc.freshness)
			requests, err := runASPKINITScript(t, cl, req, tc.steps)
			require.ErrorContains(t, err, tc.want)
			for i := 1; i < len(requests); i++ {
				pack := asPKINITAuthPack(t, requests[i])
				require.Equal(t, []byte(tc.steps[i-1].token), pack.PKAuthenticator.FreshnessToken)
			}
		})
	}
}

func TestASExchangePKINITTypedFallbackBudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int32
		kind error
	}{
		{name: "KDF", code: errorcode.KDC_ERR_NO_ACCEPTABLE_KDF, kind: pkinit.ErrNoAcceptableKDF},
		{name: "RSA to DH", code: errorcode.KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED, kind: pkinit.ErrPublicKeyEncryptionUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl, req := asPKINITClient(t, true, false)
			cl.settings.pkinitOptions.Mode = pkinit.ModeRSA
			requests, err := runASPKINITScript(t, cl, req, []asPKINITStep{{code: tc.code}, {code: tc.code}})
			require.ErrorIs(t, err, tc.kind)
			first := asPKINITAuthPack(t, requests[0])
			second := asPKINITAuthPack(t, requests[1])
			if tc.code == errorcode.KDC_ERR_NO_ACCEPTABLE_KDF {
				require.NotEmpty(t, first.SupportedKDFs)
				require.Empty(t, second.SupportedKDFs)
			} else {
				require.Nil(t, first.ClientPublicValue)
				require.NotNil(t, second.ClientPublicValue)
			}
			require.Equal(t, pkinit.ModeRSA, cl.settings.pkinitOptions.Mode)
		})
	}
}

func TestASExchangePKINITGenericFailureSkewOrdering(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cl, req := asPKINITClient(t, true, true)
		const skew = time.Hour
		serverTime := clientNow().UTC().Add(skew)
		calls := 0
		cl.sendToKDCFunc = func(b []byte, _ string) ([]byte, error) {
			var request messages.ASReq
			require.NoError(t, request.Unmarshal(b))
			calls++
			if calls == 1 {
				require.False(t, request.PAData.Contains(patype.PA_PK_AS_REQ))
				return nil, asPKINITError(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, "fresh")
			}
			require.LessOrEqual(t, calls, 4, "generic failure exceeded skew and normal preauth budgets")
			require.Equal(t, []byte("fresh"), asPKINITAuthPack(t, request).PKAuthenticator.FreshnessToken)
			response := asPKINITError(t, errorcode.KDC_ERR_PREAUTH_FAILED, "")
			// Later times must not replace the first skew correction.
			return nil, asErrorAt(response, serverTime.Add(time.Duration(calls-2)*skew))
		}
		_, err := cl.ASExchange("EXAMPLE.ORG", req, 0)
		require.ErrorContains(t, err, "kerberos error response from KDC")
		require.Equal(t, 4, calls)
		require.Equal(t, skew, cl.KDCTimeOffset())
	})
}

func TestASExchangePKINITMalformedFreshness(t *testing.T) {
	cl, req := asPKINITClient(t, false, false)
	cl.sendToKDCFunc = func([]byte, string) ([]byte, error) {
		response := asPKINITError(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")
		response.EData = []byte{0x30, 0x01}
		return nil, response
	}
	_, err := cl.ASExchange("EXAMPLE.ORG", req, 0)
	require.ErrorContains(t, err, "invalid PKINIT freshness response")
}

func TestASExchangeReferralRecursionBoundary(t *testing.T) {
	cl, req := asPKINITClient(t, false, false)
	calls := 0
	cl.sendToKDCFunc = func([]byte, string) ([]byte, error) {
		calls++
		return nil, asPKINITError(t, errorcode.KDC_ERR_WRONG_REALM, "")
	}
	_, err := cl.ASExchange("EXAMPLE.ORG", req, 0)
	require.ErrorContains(t, err, "maximum number of client referrals exceeded")
	require.Equal(t, 7, calls)
}

func TestASExchangePKINITBuildFailure(t *testing.T) {
	cl, req := asPKINITClient(t, true, false)
	cause := errors.New("identity rejected")
	cl.settings.pkinitOptions.ValidateIdentity = func(*pkinit.Identity, types.PrincipalName, string) error { return cause }
	cl.sendToKDCFunc = func([]byte, string) ([]byte, error) {
		t.Fatal("invalid identity reached transport")
		return nil, cause
	}
	_, err := cl.ASExchange("EXAMPLE.ORG", req, 0)
	require.ErrorIs(t, err, cause)
	require.ErrorContains(t, err, "could not build PKINIT request")
	require.ErrorContains(t, err, "initialize PKINIT exchange")
}

func TestASExchangePKINITDHFallback(t *testing.T) {
	for _, accept := range []bool{false, true} {
		t.Run(map[bool]string{false: "unacceptable", true: "accepted once"}[accept], func(t *testing.T) {
			cl, req := asPKINITClient(t, true, false)
			group, err := pkinit.GenerateDHKey(pkinit.MODPGroup14, 2048, rand.Reader)
			require.NoError(t, err)
			public, err := group.PublicKey()
			require.NoError(t, err)
			params := pkinit.TDDHParameters{public.Algorithm}
			if !accept {
				params = nil
			}
			encoded, err := asn1.Marshal(params)
			require.NoError(t, err)
			typed, err := asn1.Marshal(types.TypedDataSequence{{DataType: patype.TD_DH_PARAMETERS, DataValue: encoded}})
			require.NoError(t, err)
			calls := 0
			cl.sendToKDCFunc = func([]byte, string) ([]byte, error) {
				calls++
				response := asPKINITError(t, errorcode.KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED, "")
				response.EData = typed
				return nil, response
			}
			_, err = cl.ASExchange("EXAMPLE.ORG", req, 0)
			require.ErrorIs(t, err, pkinit.ErrDHParametersNotAccepted)
			wantCalls := 1
			if accept {
				wantCalls = 2
			}
			require.Equal(t, wantCalls, calls)
		})
	}
}

func asPKINITReply(t *testing.T, request messages.ASReq, accepted *pkinit.AcceptorResult, invalid bool) []byte {
	t.Helper()
	now := time.Now().UTC()
	part := messages.EncKDCRepPart{
		Key:   types.EncryptionKey{KeyType: 17, KeyValue: []byte("session-key-1234")},
		Nonce: request.ReqBody.Nonce, Flags: types.NewKrbFlags(),
		AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour),
		SRealm: request.ReqBody.Realm, SName: request.ReqBody.SName,
	}
	if invalid {
		part.Nonce++
	}
	plain, err := part.Marshal()
	require.NoError(t, err)
	reply := messages.ASRep{KDCRepFields: messages.KDCRepFields{
		PVNO: iana.PVNO, MsgType: msgtype.KRB_AS_REP,
		CRealm: request.ReqBody.Realm, CName: request.ReqBody.CName,
		Ticket: s4uTestTicket(request.ReqBody.Realm, request.ReqBody.SName.PrincipalNameString()),
		PAData: types.PADataSequence{{PADataType: patype.PA_PK_AS_REP, PADataValue: accepted.ReplyPAData}},
	}}
	reply.EncPart, err = crypto.GetEncryptedData(plain, accepted.ReplyKey, keyusage.AS_REP_ENCPART, 0)
	require.NoError(t, err)
	b, err := reply.Marshal()
	require.NoError(t, err)
	return b
}

func TestASExchangePKINITReplyKeyPublication(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "nonce mismatch"}[invalid], func(t *testing.T) {
			cl, req := asPKINITClient(t, true, false)
			DisablePAReqEncPARep(true)(cl.settings)
			cl.settings.pkinitOptions.ValidateKDCSigner = func(*pkinit.VerifiedSignedData) error { return nil }
			var replyKey types.EncryptionKey
			cl.sendToKDCFunc = func(b []byte, _ string) ([]byte, error) {
				_, published := cl.takePKINITReplyKey("EXAMPLE.ORG")
				require.False(t, published)
				var request messages.ASReq
				require.NoError(t, request.Unmarshal(b))
				accepted, err := pkinit.AcceptExchange(&request, pkinit.AcceptorOptions{
					Identity:       cl.settings.pkinitOptions.Identity,
					ValidateSigner: func(*pkinit.VerifiedSignedData) error { return nil },
				})
				require.NoError(t, err)
				replyKey = accepted.ReplyKey
				return asPKINITReply(t, request, accepted, invalid), nil
			}
			_, err := cl.ASExchange("EXAMPLE.ORG", req, 0)
			if !invalid {
				require.NoError(t, err)
			}
			published, ok := cl.takePKINITReplyKey("EXAMPLE.ORG")
			require.Equal(t, !invalid, ok)
			if invalid {
				require.ErrorContains(t, err, "PKINIT AS_REP is not valid")
			} else {
				require.Equal(t, replyKey, published)
			}
		})
	}
}

func asFASTPeerState(t *testing.T, peer *fastState, b []byte) messages.ASReq {
	t.Helper()
	var request messages.ASReq
	require.NoError(t, request.Unmarshal(b))
	require.Len(t, request.PAData, 1)
	wrapped, err := request.PAData[0].GetPAFXFastRequest()
	require.NoError(t, err)
	var armor messages.APReq
	require.NoError(t, armor.Unmarshal(wrapped.ArmoredData.Armor.ArmorValue))
	require.NoError(t, armor.DecryptAuthenticatorWithKeyUsage(peer.armor.key, keyusage.AP_REQ_AUTHENTICATOR))
	peer.armorKey, err = crypto.KRBFXCF2(armor.Authenticator.SubKey, peer.armor.key, []byte("subkeyarmor"), []byte("ticketarmor"))
	require.NoError(t, err)
	return request
}

func TestASExchangeFASTErrorCause(t *testing.T) {
	for _, tt := range []struct {
		name       string
		code       int32
		referral   int
		nonceDelta int
		rootCause  string
		context    string
	}{
		{
			name: "terminal", code: errorcode.KDC_ERR_CLIENT_REVOKED, referral: 0, nonceDelta: 0,
			rootCause: krberror.KDCError, context: "kerberos error response from KDC",
		},
		{
			name: "referral limit", code: errorcode.KDC_ERR_WRONG_REALM, referral: 6, nonceDelta: 0,
			rootCause: krberror.KRBMsgError, context: "maximum number of client referrals exceeded",
		},
		{
			name: "invalid armored response", code: errorcode.KDC_ERR_CLIENT_REVOKED, referral: 0, nonceDelta: -1,
			rootCause: krberror.KRBMsgError, context: "invalid FAST error response",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cl, peer, req := newFASTTestState(t)
			cl.settings.assumePreAuthentication = true
			const nonce = 42
			req.ReqBody.Nonce = nonce
			calls := 0
			cl.sendToKDCFunc = func(b []byte, _ string) ([]byte, error) {
				calls++
				request := asFASTPeerState(t, peer, b)
				inner := asPKINITError(t, tt.code, "")
				encoded, err := inner.Marshal()
				require.NoError(t, err)
				pa, err := types.NewPAFXErrorPAData(types.PAFXError(encoded))
				require.NoError(t, err)
				return nil, fastTestError(t, peer, request.ReqBody.Nonce+tt.nonceDelta, types.PADataSequence{pa})
			}
			_, err := cl.ASExchange("EXAMPLE.ORG", req, tt.referral)
			require.ErrorContains(t, err, tt.context)
			require.NotContains(t, err.Error(), "%!")
			var classified krberror.Krberror
			require.ErrorAs(t, err, &classified)
			require.Equal(t, tt.rootCause, classified.RootCause)
			require.Equal(t, 1, calls)

			inner, found := errors.AsType[messages.KRBError](err)
			if tt.nonceDelta != 0 {
				require.False(t, found, "a rejected armored response must not expose a KDC error")
				return
			}
			require.True(t, found)
			require.Equal(t, tt.code, inner.ErrorCode)
			require.Equal(t, "scripted", inner.EText)
		})
	}
}

func TestASExchangeNormalPreAuthBudgets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		code  int32
		calls int
		want  string
	}{
		{name: "required once", code: errorcode.KDC_ERR_PREAUTH_REQUIRED, calls: 2, want: "kerberos error response from KDC"},
		{name: "more data five rounds", code: errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, calls: 6, want: "maximum FAST pre-authentication rounds exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl, _, req := newFASTTestState(t)
			cl.settings.fastArmor = nil
			info, err := asn1.Marshal(types.ETypeInfo2{{EType: 17}})
			require.NoError(t, err)
			methodData, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
			require.NoError(t, err)
			calls := 0
			cl.sendToKDCFunc = func([]byte, string) ([]byte, error) {
				calls++
				response := asPKINITError(t, tc.code, "")
				response.EData = methodData
				return nil, response
			}
			_, err = cl.ASExchange("EXAMPLE.ORG", req, 0)
			require.ErrorContains(t, err, tc.want)
			require.Equal(t, tc.calls, calls)
		})
	}
}

func TestASExchangePKINITTypedBudgetShared(t *testing.T) {
	cl, req := asPKINITClient(t, true, false)
	cl.settings.pkinitOptions.Mode = pkinit.ModeRSA
	_, err := runASPKINITScript(t, cl, req, []asPKINITStep{
		{code: errorcode.KDC_ERR_NO_ACCEPTABLE_KDF},
		{code: errorcode.KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED},
	})
	require.ErrorIs(t, err, pkinit.ErrPublicKeyEncryptionUnsupported)
}

func TestASExchangePKINITReplyOrdering(t *testing.T) {
	for _, tc := range []struct {
		name   string
		assume bool
		want   string
	}{
		{name: "before negotiation", want: "KDC returned AS_REP before PKINIT negotiation"},
		{name: "missing PKINIT reply", assume: true, want: "invalid PA-PK-AS-REP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl, req := asPKINITClient(t, tc.assume, false)
			cl.sendToKDCFunc = func([]byte, string) ([]byte, error) {
				reply := messages.ASRep{KDCRepFields: messages.KDCRepFields{
					PVNO: iana.PVNO, MsgType: msgtype.KRB_AS_REP,
					CRealm: req.ReqBody.Realm, CName: req.ReqBody.CName,
					Ticket:  s4uTestTicket(req.ReqBody.Realm, req.ReqBody.SName.PrincipalNameString()),
					EncPart: types.EncryptedData{EType: 17, Cipher: []byte("unused")},
				}}
				b, err := reply.Marshal()
				require.NoError(t, err)
				return b, nil
			}
			_, err := cl.ASExchange("EXAMPLE.ORG", req, 0)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func asFASTInnerRequest(t *testing.T, peer *fastState, b []byte) messages.ASReq {
	t.Helper()
	request := asFASTPeerState(t, peer, b)
	wrapped, err := request.PAData[0].GetPAFXFastRequest()
	require.NoError(t, err)
	plain, err := crypto.DecryptEncPart(wrapped.ArmoredData.EncFastReq, peer.armorKey, keyusage.FAST_ENC)
	require.NoError(t, err)
	var inner types.KrbFastReq
	require.NoError(t, inner.Unmarshal(plain))
	require.NoError(t, request.ReqBody.Unmarshal(inner.ReqBody.Bytes))
	request.PAData = inner.PAData
	return request
}

func asFASTPKINITReply(t *testing.T, peer *fastState, replyBytes []byte, nonce int, invalid bool) []byte {
	t.Helper()
	if nonce < 0 || nonce > math.MaxInt32 {
		t.Fatal("nonce outside AS-REQ range")
		return nil
	}
	var reply messages.ASRep
	require.NoError(t, reply.Unmarshal(replyBytes))
	ticketBytes, err := reply.Ticket.Marshal()
	require.NoError(t, err)
	et, err := crypto.GetEtype(peer.armorKey.KeyType)
	require.NoError(t, err)
	checksum, err := et.GetChecksumHash(peer.armorKey.KeyValue, ticketBytes, keyusage.FAST_FINISHED)
	require.NoError(t, err)
	if invalid {
		checksum[0] ^= 0xff
	}
	now := time.Now().UTC()
	response := types.KrbFastResponse{
		PAData: reply.PAData, Nonce: uint32(nonce),
		Finished: types.KrbFastFinished{
			Timestamp: now, Usec: now.Nanosecond() / int(time.Microsecond),
			CRealm: reply.CRealm, CName: reply.CName,
			TicketChecksum: types.Checksum{CksumType: et.GetHashID(), Checksum: checksum},
		},
	}
	encoded, err := response.Marshal()
	require.NoError(t, err)
	encrypted, err := crypto.GetEncryptedData(encoded, peer.armorKey, keyusage.FAST_REP, 0)
	require.NoError(t, err)
	pa, err := types.NewPAFXFastReplyPAData(types.PAFXFastReply{ArmoredData: types.KrbFastArmoredRep{EncFastRep: encrypted}})
	require.NoError(t, err)
	reply.PAData = types.PADataSequence{pa}
	b, err := reply.Marshal()
	require.NoError(t, err)
	return b
}

func TestASExchangeFASTPKINITReply(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "finished checksum mismatch"}[invalid], func(t *testing.T) {
			cl, req := asPKINITClient(t, true, false)
			armorClient, peer, _ := newFASTTestState(t)
			cl.settings.fastArmor = armorClient.settings.fastArmor
			DisablePAReqEncPARep(true)(cl.settings)
			cl.settings.pkinitOptions.ValidateKDCSigner = func(*pkinit.VerifiedSignedData) error { return nil }
			cl.sendToKDCFunc = func(b []byte, _ string) ([]byte, error) {
				request := asFASTInnerRequest(t, peer, b)
				accepted, err := pkinit.AcceptExchange(&request, pkinit.AcceptorOptions{
					Identity:       cl.settings.pkinitOptions.Identity,
					ValidateSigner: func(*pkinit.VerifiedSignedData) error { return nil },
				})
				require.NoError(t, err)
				replyBytes := asPKINITReply(t, request, accepted, false)
				return asFASTPKINITReply(t, peer, replyBytes, request.ReqBody.Nonce, invalid), nil
			}
			_, err := cl.ASExchange("EXAMPLE.ORG", req, 0)
			if invalid {
				require.ErrorContains(t, err, "FAST PKINIT AS_REP is not valid")
			} else {
				require.NoError(t, err)
			}
			_, published := cl.takePKINITReplyKey("EXAMPLE.ORG")
			require.Equal(t, !invalid, published)
		})
	}
}

func TestASExchangeInitialRequestBytesAndAliasing(t *testing.T) {
	cl, _, req := newFASTTestState(t)
	cl.settings.fastArmor = nil
	req.PAData = make(types.PADataSequence, 1, 4)
	req.PAData[0] = types.PAData{PADataType: patype.PA_PAC_REQUEST, PADataValue: []byte{1, 2, 3}}
	DisablePAReqEncPARep(false)(cl.settings)
	expected := req
	expected.PAData = append(append(types.PADataSequence(nil), req.PAData...), types.PAData{PADataType: patype.PA_REQ_ENC_PA_REP})
	want, err := expected.Marshal()
	require.NoError(t, err)
	cause := errors.New("stop after capture")
	cl.sendToKDCFunc = func(b []byte, _ string) ([]byte, error) {
		require.Equal(t, want, b)
		return nil, cause
	}
	_, err = cl.ASExchange("EXAMPLE.ORG", req, 0)
	require.ErrorIs(t, err, cause)
	require.Len(t, req.PAData, 1, "caller slice header must not change")
	require.Equal(t, expected.PAData, req.PAData[:2], "caller backing array remains shared")
}

func TestASExchangePKINITPreparationAliasing(t *testing.T) {
	cl, req := asPKINITClient(t, false, false)
	req.PAData = make(types.PADataSequence, 4, 8)
	req.PAData[0] = types.PAData{PADataType: patype.PA_ENC_TIMESTAMP}
	req.PAData[1] = types.PAData{PADataType: patype.PA_PK_AS_REQ}
	req.PAData[2] = types.PAData{PADataType: patype.PA_PK_OCSP_RESPONSE}
	req.PAData[3] = types.PAData{PADataType: patype.PA_PAC_REQUEST}
	var sent messages.ASReq
	cl.sendToKDCFunc = func(b []byte, _ string) ([]byte, error) {
		require.NoError(t, sent.Unmarshal(b))
		return nil, asPKINITError(t, errorcode.KDC_ERR_CLIENT_REVOKED, "")
	}
	_, err := cl.ASExchange("EXAMPLE.ORG", req, 0)
	require.Error(t, err)
	require.Len(t, sent.PAData, 3)
	require.Equal(t, types.PADataSequence{
		{PADataType: patype.PA_PAC_REQUEST},
		{PADataType: patype.PA_REQ_ENC_PA_REP},
		{PADataType: patype.PA_AS_FRESHNESS},
	}, req.PAData[:3])
	require.Len(t, req.PAData, 4)
}
