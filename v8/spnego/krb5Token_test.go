package spnego

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/asn1tools"
	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	// #nosec G101 -- this AP-REQ vector belongs to the TEST.GOKRB5 test realm.
	KRB5TokenHex = "6082026306092a864886f71201020201006e8202523082024ea003020105a10302010ea20703050000000000a382015d" +
		"6182015930820155a003020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b" +
		"10686f73742e746573742e676f6b726235a382011830820114a003020112a103020103a28201060482010230621d868c" +
		"97f30bf401e03bbffcd724bd9d067dce2afc31f71a356449b070cdafcc1ff372d0eb1e7a708b50c0152f3996c45b1ea3" +
		"12a803907fb97192d39f20cdcaea29876190f51de6e2b4a4df0460122ed97f363434e1e120b0e76c172b4424a5369871" +
		"52ac0b73013ab88af4b13a3fcdc63f739039dd46d839709cf5b51bb0ce6cb3af05fab3844caac280929955495235e9d0" +
		"424f8a1fb9b4bd4f6bba971f40b97e9da60b9dabfcf0b1feebfca02c9a19b327a0004aa8e19192726cf347561fa8ac74" +
		"afad5d6a264e50cf495b93aac86c77b2bc2d184234f6c2767dbea431485a25687b9044a20b601e968efaefffa1fc5283" +
		"ff32aa6a53cb6c5cdd2eddcb26a481d73081d4a003020112a103020103a281c70481c4a1b29e420324f7edf9efae39df" +
		"7bcaaf196a3160cf07e72f52a4ef8a965721b2f3343719c50699046e4fcc18ca26c2bfc7e4a9eddfc9d9cfc57ff2f6bd" +
		"bbd1fc40ac442195bc669b9a0dbba12563b3e4cac9f4022fc01b8aa2d1ab84815bb078399ff7f4d5f9815eef896a0c7e" +
		"3c049e6fd9932b97096cdb5861425b9d81753d0743212ded1a0fb55a00bf71a46be5ce5e1c8a5cc327b914347d9efcb6" +
		"cb31ca363b1850d95c7b6c4c3cc6301615ad907318a0c5379d343610fab17eca9c7dc0a5a60658"
	AuthChksum = "100000000000000000000000000000000000000030000000"
)

func TestKRB5Token_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(KRB5TokenHex)
	if err != nil {
		t.Fatalf("Error decoding KRB5Token hex: %v", err)
	}
	var mt KRB5Token
	err = mt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshalling KRB5Token: %v", err)
	}
	assert.Equal(t, gssapi.OIDKRB5.OID(), mt.OID, "KRB5Token OID not as expected.")
	assert.Equal(t, []byte{1, 0}, mt.tokID, "TokID not as expected")
	assert.Equal(t, msgtype.KRB_AP_REQ, mt.APReq.MsgType, "KRB5Token AP_REQ does not have the right message type.")
	assert.Equal(t, int32(0), mt.KRBError.ErrorCode, "KRBError in KRB5Token does not indicate no error.")
	assert.Equal(
		t,
		int32(18),
		mt.APReq.EncryptedAuthenticator.EType,
		"Authenticator within AP_REQ does not have the etype expected.",
	)
}

func decodeTestTokenID(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	return decoded
}

func testKRB5TokenWithID(id []byte, raw bool) *KRB5Token {
	token := new(KRB5Token)
	token.tokID = id
	token.raw = raw
	return token
}

func TestKRB5TokenClassificationAndVerification(t *testing.T) {
	tokenID := func(value string) []byte { return decodeTestTokenID(t, value) }

	apReq := testKRB5TokenWithID(tokenID(TOK_ID_KRB_AP_REQ), false)
	apRep := testKRB5TokenWithID(tokenID(TOK_ID_KRB_AP_REP), false)
	krbError := testKRB5TokenWithID(tokenID(TOK_ID_KRB_ERROR), false)
	unknown := testKRB5TokenWithID([]byte{0xff, 0xff}, false)
	assert.True(t, apReq.IsAPReq())
	assert.True(t, apRep.IsAPRep())
	assert.True(t, krbError.IsKRBError())
	assert.False(t, unknown.IsAPReq())
	assert.False(t, unknown.IsAPRep())
	assert.False(t, unknown.IsKRBError())
	assert.Equal(
		t,
		[]int{gssapi.ContextFlagInteg},
		appendContextFlag([]int{gssapi.ContextFlagInteg}, gssapi.ContextFlagInteg),
	)
	assert.Equal(
		t,
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf},
		appendContextFlag([]int{gssapi.ContextFlagInteg}, gssapi.ContextFlagConf),
	)

	{
		_, err := testKRB5TokenWithID([]byte{0xff, 0xff}, true).Marshal()
		require.Error(t, err)
	}
	{
		_, err := krbError.Marshal()
		require.Error(t, err)
	}
	{
		ok, status := apRep.Verify()
		require.False(t, ok)
		require.Equal(t, gssapi.StatusNoContext, status.Code)
	}
	{
		ok, status := unknown.Verify()
		require.False(t, ok)
		require.Equal(t, gssapi.StatusDefectiveToken, status.Code)
	}
	{
		ok, status := krbError.Verify()
		require.False(t, ok)
		require.Equal(t, gssapi.StatusDefectiveToken, status.Code)
	}
	krbError.KRBError.MsgType = msgtype.KRB_ERROR
	{
		ok, status := krbError.Verify()
		require.True(t, ok)
		require.Equal(t, gssapi.StatusUnavailable, status.Code)
	}
}

func TestKRB5TokenRejectsMalformedFraming(t *testing.T) {
	tokenID := func(value string) []byte { return decodeTestTokenID(t, value) }
	wrapped := func(oid asn1.ObjectIdentifier, id []byte, payload []byte) []byte {
		header, err := asn1.Marshal(oid)
		require.NoError(t, err)
		return asn1tools.AddASNAppTag(append(append(header, id...), payload...), 0)
	}
	badInputs := [][]byte{
		{0x60, 0x00},
		wrapped(asn1.ObjectIdentifier{1, 2, 3}, tokenID(TOK_ID_KRB_AP_REQ), nil),
		wrapped(gssapi.OIDKRB5.OID(), nil, nil),
		wrapped(gssapi.OIDKRB5.OID(), tokenID(TOK_ID_KRB_AP_REQ), []byte{1}),
		wrapped(gssapi.OIDKRB5.OID(), tokenID(TOK_ID_KRB_AP_REP), []byte{1}),
		wrapped(gssapi.OIDKRB5.OID(), tokenID(TOK_ID_KRB_ERROR), []byte{1}),
	}
	for i, input := range badInputs {
		var token KRB5Token
		require.Error(t, token.Unmarshal(input), "fixture %d", i)
	}
}

func TestKRB5TokenMarshalRejectsInvalidOID(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(KRB5TokenHex)
	require.NoError(t, err)
	var token KRB5Token
	require.NoError(t, token.Unmarshal(b))
	encoded, err := token.Marshal()
	require.NoError(t, err)
	require.Equal(t, b, encoded)

	token.OID = asn1.ObjectIdentifier{1}
	encoded, err = token.Marshal()
	require.ErrorContains(t, err, "marshal Kerberos mechanism OID:")
	require.ErrorAs(t, err, new(asn1.StructuralError))
	require.Empty(t, encoded)
}

func TestRawKerberosTokenUnmarshalErrors(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name        string
		input       []byte
		wantContext string
	}{
		{name: "request", input: []byte{0x6e}, wantContext: "unmarshal raw AP-REQ:"},
		{name: "reply", input: []byte{0x6f}, wantContext: "unmarshal raw AP-REP:"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var token KRB5Token
			err := token.Unmarshal(tt.input)
			require.ErrorContains(t, err, tt.wantContext)
			require.ErrorAs(t, err, new(asn1.SyntaxError))
		})
	}
}

func TestRawAPReqPreservesProtocolError(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(KRB5TokenHex)
	require.NoError(t, err)
	var token KRB5Token
	require.NoError(t, token.Unmarshal(b))
	token.APReq.MsgType = msgtype.KRB_AS_REQ
	raw, err := token.APReq.Marshal()
	require.NoError(t, err)

	err = new(KRB5Token).Unmarshal(raw)
	var protocolErr messages.KRBError
	require.ErrorAs(t, err, &protocolErr)
	require.IsType(t, protocolErr, err)
	require.EqualValues(t, errorcode.KRB_AP_ERR_MSG_TYPE, protocolErr.ErrorCode)
}

func TestKRB5TokenAPREQRetainsDelegationError(t *testing.T) {
	t.Parallel()

	cl := client.NewWithPassword("user", "EXAMPLE.COM", "", config.New())
	var options KRB5TokenAPREQOptions
	options.Delegate = true
	var ticket messages.Ticket
	var key types.EncryptionKey
	_, err := NewKRB5TokenAPREQWithOptions(cl, ticket, key, options)
	require.ErrorContains(t, err, "obtain delegated Kerberos credential:")
	require.ErrorContains(t, err, "service ticket is not trusted for delegation")
}

func TestKRB5Token_newAuthenticatorChksum(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(AuthChksum)
	if err != nil {
		t.Fatalf("Error decoding KRB5Token hex: %v", err)
	}
	cb := newAuthenticatorChksum([]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf})
	assert.Equal(t, b, cb, "SPNEGO Authenticator checksum not as expected")
}

// Test with explicit subkey generation.
func TestKRB5Token_newAuthenticatorWithSubkeyGeneration(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING,
	})
	var etypeID int32 = 18
	keyLen := 32 // etypeID 18 refers to AES256 -> 32 bytes key
	a, err := krb5TokenAuthenticator(creds, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf})
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}
	if err := a.GenerateSeqNumberAndSubKey(etypeID, keyLen); err != nil {
		t.Fatal(err)
	}
	assert.Equal(
		t,
		int32(32771),
		a.Cksum.CksumType,
		"Checksum type in authenticator for SPNEGO mechtoken not as expected.",
	)
	assert.Equal(t, etypeID, a.SubKey.KeyType, "Subkey not of the expected type.")
	assert.Equal(t, keyLen, len(a.SubKey.KeyValue), "Subkey value not of the right length")
	var nz bool
	for _, b := range a.SubKey.KeyValue {
		if b != byte(0) {
			nz = true
		}
	}
	assert.True(t, nz, "subkey not initialised")
	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber > 0
	}), "Sequence number is not greater than zero")
	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber <= math.MaxUint32
	}))
}

// Test without subkey generation.
func TestKRB5Token_newAuthenticator(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING,
	})
	a, err := krb5TokenAuthenticator(creds, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf})
	if err != nil {
		t.Fatalf("Error creating authenticator: %v", err)
	}
	assert.Equal(
		t,
		int32(32771),
		a.Cksum.CksumType,
		"Checksum type in authenticator for SPNEGO mechtoken not as expected.",
	)
	assert.Equal(t, int32(0), a.SubKey.KeyType, "Subkey not of the expected type.")
	assert.Nil(t, a.SubKey.KeyValue, "Subkey should not be set.")

	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber > 0
	}), "Sequence number is not greater than zero")
	assert.Condition(t, assert.Comparison(func() bool {
		return a.SeqNumber <= math.MaxUint32
	}))
}

func TestNewAPREQKRB5Token_and_Marshal(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING,
	})
	cl := client.Client{
		Config: nil,

		Credentials: creds,
	}

	var tkt messages.Ticket
	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = tkt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: make([]byte, 32),
	}

	mt, err := NewKRB5TokenAPREQ(&cl, tkt, key, []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}, []int{})
	if err != nil {
		t.Fatalf("Error creating KRB5Token: %v", err)
	}
	mb, err := mt.Marshal()
	if err != nil {
		t.Fatalf("Error unmarshalling KRB5Token: %v", err)
	}
	err = mt.Unmarshal(mb)
	if err != nil {
		t.Fatalf("Error unmarshalling KRB5Token: %v", err)
	}
	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}, mt.OID, "KRB5Token OID not as expected.")
	assert.Equal(t, []byte{1, 0}, mt.tokID, "TokID not as expected")
	assert.Equal(t, msgtype.KRB_AP_REQ, mt.APReq.MsgType, "KRB5Token AP_REQ does not have the right message type.")
	assert.Equal(t, int32(0), mt.KRBError.ErrorCode, "KRBError in KRB5Token does not indicate no error.")
	assert.Equal(t, testdata.TEST_REALM, mt.APReq.Ticket.Realm, "ticket realm")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, mt.APReq.Ticket.SName.NameString, "ticket service")
	assert.Equal(t, int32(18), mt.APReq.EncryptedAuthenticator.EType, "authenticator enctype")
}

func TestNewAPREQKRB5TokenWithOptions(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING,
	})
	cl := client.Client{
		Config:      nil,
		Credentials: creds,
	}
	var tkt messages.Ticket
	ticketBytes, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(ticketBytes))
	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}
	bindings := &gssapi.ChannelBindings{
		InitiatorAddress: gssapi.ChannelBindingAddress{AddressType: 0, Address: nil},
		AcceptorAddress:  gssapi.ChannelBindingAddress{AddressType: 0, Address: nil},
		ApplicationData:  []byte("tls-server-end-point:test"),
	}
	delegated := []byte{0x76, 0x00}

	mt, err := NewKRB5TokenAPREQWithOptions(&cl, tkt, key, KRB5TokenAPREQOptions{
		APOptions:           nil,
		MechTypes:           nil,
		Delegate:            false,
		ForceDelegation:     false,
		DelegationAddresses: nil,

		GSSAPIFlags:         []int{gssapi.ContextFlagInteg, gssapi.ContextFlagDeleg},
		ChannelBindings:     bindings,
		DelegatedCredential: delegated,
	})
	require.NoError(t, err)
	require.NoError(t, mt.APReq.DecryptAuthenticator(key))

	var checksum gssapi.AuthenticatorChecksum
	require.NoError(t, checksum.Unmarshal(mt.APReq.Authenticator.Cksum.Checksum))
	assert.Equal(t, bindings.MD5Hash(), checksum.Bnd)
	assert.Equal(t, uint16(1), checksum.DelegationOption)
	assert.True(t, bytes.Equal(delegated, checksum.Deleg))
}

func TestNewAPREQKRB5TokenMutualAndCBTOptions(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING,
	})
	cl := client.Client{
		Config:      nil,
		Credentials: creds,
	}
	var tkt messages.Ticket
	ticketBytes, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	require.NoError(t, err)
	require.NoError(t, tkt.Unmarshal(ticketBytes))
	key := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}

	mt, err := NewKRB5TokenAPREQWithOptions(&cl, tkt, key, KRB5TokenAPREQOptions{
		APOptions:           nil,
		MechTypes:           nil,
		DelegatedCredential: nil,
		Delegate:            false,
		ForceDelegation:     false,
		DelegationAddresses: nil,

		GSSAPIFlags: []int{gssapi.ContextFlagMutual},
		ChannelBindings: &gssapi.ChannelBindings{
			InitiatorAddress: gssapi.ChannelBindingAddress{AddressType: 0, Address: nil},
			AcceptorAddress:  gssapi.ChannelBindingAddress{AddressType: 0, Address: nil},
			ApplicationData:  []byte("binding"),
		},
	})
	require.NoError(t, err)
	require.NoError(t, mt.APReq.DecryptAuthenticator(key))
	assert.True(t, types.IsFlagSet(&mt.APReq.APOptions, flags.APOptionMutualRequired))

	entries, err := mt.APReq.Authenticator.AuthorizationData.EntriesOfType(adtype.ADAuthDataAPOptions)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	options, err := entries[0].GetADAuthDataAPOptions()
	require.NoError(t, err)
	assert.Equal(t, msflags.KERB_AP_OPTIONS_CBT, msflags.APOptions(options))

	wantDER, err := asn1.Marshal(types.AuthorizationData{entries[0]})
	require.NoError(t, err)
	require.Contains(t, mt.APReq.Authenticator.AuthorizationData, types.AuthorizationDataEntry{
		ADType: adtype.ADIfRelevant,
		ADData: wantDER,
	})
}

func TestNewAPREQKRB5TokenRejectsDelegationWithoutFlag(t *testing.T) {
	t.Parallel()
	creds := credentials.New("hftsai", testdata.TEST_REALM)
	creds.SetCName(types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: testdata.TEST_PRINCIPALNAME_NAMESTRING,
	})
	cl := client.Client{
		Config:      nil,
		Credentials: creds,
	}

	var ticket messages.Ticket
	var key types.EncryptionKey
	_, err := NewKRB5TokenAPREQWithOptions(&cl, ticket, key, KRB5TokenAPREQOptions{
		GSSAPIFlags:         nil,
		APOptions:           nil,
		MechTypes:           nil,
		ChannelBindings:     nil,
		Delegate:            false,
		ForceDelegation:     false,
		DelegationAddresses: nil,

		DelegatedCredential: []byte{1},
	})
	require.Error(t, err)
}
