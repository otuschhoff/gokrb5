package client

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const fxFastArmorAPRequest int32 = 1

const fastTGSOuterPADataCount = 2 // PA-TGS-REQ and PA-FX-FAST.

var errNilFASTState = errors.New("FAST state is nil")

type fastState struct {
	active        bool
	armor         fastArmorCredentials
	armorValue    []byte
	armorKey      types.EncryptionKey
	replyKey      types.EncryptionKey
	sentChallenge bool
}

func (cl *Client) hasFASTArmor() bool {
	return cl.settings.fastArmor != nil || cl.settings.fastArmorKeytab != nil
}

func (cl *Client) newFASTState(realm string, activate bool) (*fastState, error) {
	if !cl.hasFASTArmor() {
		if cl.settings.RequireFAST() {
			return nil, errors.New("FAST is required but no armor credentials are configured")
		}
		return nil, nil //nolint:nilnil // Optional FAST is disabled, not an initialization failure.
	}
	if session, ok := cl.sessions.get(realm); ok {
		activate = activate || session.supportedEncryptionTypes()&msflags.SupportedEncTypeFAST != 0
	}
	state := new(fastState)
	if activate {
		if err := state.activate(cl, realm); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func (cl *Client) newTGSFASTState(realm string) *fastState {
	enabled := cl.settings.RequireFAST()
	if session, ok := cl.sessions.get(realm); ok {
		enabled = enabled || session.supportedEncryptionTypes()&msflags.SupportedEncTypeFAST != 0
	}
	if !enabled {
		return nil
	}
	state := new(fastState)
	state.active = true
	return state
}

func (state *fastState) activate(cl *Client, realm string) error {
	if state.active {
		return nil
	}
	armor, err := cl.fastArmorForRealm(realm)
	if err != nil {
		return err
	}
	if len(armor.cname.NameString) == 0 {
		armor.cname = cl.Credentials.CName()
	}
	if armor.realm == "" {
		armor.realm = cl.Credentials.Realm()
	}
	if !isFASTArmorTGT(armor.ticket, realm) {
		return fmt.Errorf("FAST armor ticket is not a TGT for realm %s", realm)
	}
	armorValue, armorKey, err := cl.buildFASTArmor(armor)
	if err != nil {
		return err
	}
	state.active = true
	state.armor = armor
	state.armorValue = armorValue
	state.armorKey = armorKey
	return nil
}

func isFASTArmorTGT(ticket messages.Ticket, realm string) bool {
	name := ticket.SName.NameString
	return len(name) >= tgtPrincipalComponents && strings.EqualFold(name[0], tgtServiceName) &&
		types.RealmEqual(name[len(name)-1], realm)
}

func (cl *Client) buildFASTArmor(armor fastArmorCredentials) ([]byte, types.EncryptionKey, error) {
	et, err := crypto.GetEtype(armor.key.KeyType)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("FAST armor session key: %w", err)
	}
	auth, err := types.NewAuthenticator(armor.realm, armor.cname)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("create FAST armor authenticator: %w", err)
	}
	now := clientNow().UTC().Add(cl.KDCTimeOffset())
	auth.CTime = now.Truncate(time.Second)
	auth.Cusec = now.Nanosecond() / int(time.Microsecond)
	if ierr := auth.GenerateSeqNumberAndSubKey(armor.key.KeyType, et.GetKeyByteSize()); ierr != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("create FAST armor subkey: %w", ierr)
	}
	apReq, err := messages.NewAPReqWithKeyUsage(armor.ticket, armor.key, auth, keyusage.AP_REQ_AUTHENTICATOR)
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("create FAST armor AP-REQ: %w", err)
	}
	armorValue, err := apReq.Marshal()
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("marshal FAST armor AP-REQ: %w", err)
	}
	armorKey, err := crypto.KRBFXCF2(auth.SubKey, armor.key, []byte("subkeyarmor"), []byte("ticketarmor"))
	if err != nil {
		return nil, types.EncryptionKey{}, fmt.Errorf("derive FAST armor key: %w", err)
	}
	return armorValue, armorKey, nil
}

func (cl *Client) fastArmorForRealm(realm string) (fastArmorCredentials, error) {
	if cl.settings.fastArmor != nil {
		return *cl.settings.fastArmor, nil
	}
	kt := cl.settings.fastArmorKeytab
	if kt == nil {
		return fastArmorCredentials{}, errors.New("FAST armor credentials are not configured")
	}
	cl.fastArmorMux.Lock()
	defer cl.fastArmorMux.Unlock()
	principals := kt.Principals()
	if len(principals) == 0 {
		return fastArmorCredentials{}, errors.New("FAST armor keytab contains no principals")
	}
	principal := preferredArmorPrincipal(principals)
	cname := types.PrincipalName{NameType: principal.NameType, NameString: append([]string(nil), principal.Components...)}
	if cname.NameType == 0 {
		cname.NameType = nametype.KRB_NT_PRINCIPAL
	}
	if cl.fastArmorCl == nil {
		cl.fastArmorCl = NewFromPrincipalName(cname, principal.Realm, cl.Config)
		cl.fastArmorCl.Credentials.WithKeytab(kt)
		cl.fastArmorCl.sendToKDCFunc = cl.sendToKDCFunc
		if err := cl.fastArmorCl.Login(); err != nil {
			cl.fastArmorCl.Destroy()
			cl.fastArmorCl = nil
			return fastArmorCredentials{}, fmt.Errorf("acquire FAST armor TGT: %w", err)
		}
	}
	if !types.RealmEqual(principal.Realm, realm) {
		if err := cl.fastArmorCl.ensureValidSession(realm); err != nil {
			return fastArmorCredentials{}, fmt.Errorf("acquire FAST cross-realm armor TGT: %w", err)
		}
	}
	ticket, key, err := cl.fastArmorCl.sessionTGT(realm)
	if err != nil {
		return fastArmorCredentials{}, fmt.Errorf("read FAST armor TGT: %w", err)
	}
	return fastArmorCredentials{ticket: ticket, key: key, cname: cname, realm: principal.Realm}, nil
}

func preferredArmorPrincipal(principals []keytab.Principal) keytab.Principal {
	for _, candidate := range principals {
		if len(candidate.Components) == 1 && strings.HasSuffix(candidate.Components[0], "$") {
			return candidate
		}
	}
	return principals[0]
}

func (state *fastState) wrapASRequest(request messages.ASReq) (messages.ASReq, error) {
	if state == nil {
		return request, errNilFASTState
	}
	body, err := request.ReqBody.Marshal()
	if err != nil {
		return request, fmt.Errorf("marshal FAST inner request body: %w", err)
	}
	et, err := crypto.GetEtype(state.armorKey.KeyType)
	if err != nil {
		return request, fmt.Errorf("select FAST AS armor encryption type: %w", err)
	}
	checksum, err := et.GetChecksumHash(state.armorKey.KeyValue, body, keyusage.FAST_REQ_CHKSUM)
	if err != nil {
		return request, fmt.Errorf("checksum FAST request body: %w", err)
	}
	fastRequest := types.NewKrbFastReq(types.NewKrbFlags(), append(types.PADataSequence(nil), request.PAData...), body)
	plain, err := fastRequest.Marshal()
	if err != nil {
		return request, fmt.Errorf("marshal FAST request: %w", err)
	}
	encrypted, err := crypto.GetEncryptedData(plain, state.armorKey, keyusage.FAST_ENC, 0)
	if err != nil {
		return request, fmt.Errorf("encrypt FAST request: %w", err)
	}
	pa, err := types.NewPAFXFastRequestPAData(types.PAFXFastRequest{ArmoredData: types.KrbFastArmoredReq{
		Armor:       types.KrbFastArmor{ArmorType: fxFastArmorAPRequest, ArmorValue: state.armorValue},
		ReqChecksum: types.Checksum{CksumType: et.GetHashID(), Checksum: checksum},
		EncFastReq:  encrypted,
	}})
	if err != nil {
		return request, fmt.Errorf("marshal PA-FX-FAST request: %w", err)
	}
	request.PAData = types.PADataSequence{pa}
	return request, nil
}

func (state *fastState) wrapTGSRequest(
	request messages.TGSReq,
	tgt messages.Ticket,
	sessionKey types.EncryptionKey,
) (messages.TGSReq, error) {
	if state == nil {
		return request, errNilFASTState
	}
	subkey, apReqBytes, err := request.SetPADataWithSubkey(tgt, sessionKey)
	if err != nil {
		return request, krberror.Errorf(err, krberror.KRBMsgError, "prepare FAST PA-TGS-REQ")
	}
	armorKey, err := crypto.KRBFXCF2(subkey, sessionKey, []byte("subkeyarmor"), []byte("ticketarmor"))
	if err != nil {
		return request, fmt.Errorf("derive implicit FAST armor key: %w", err)
	}
	state.armorKey = armorKey
	state.replyKey = subkey
	body, err := request.ReqBody.Marshal()
	if err != nil {
		return request, fmt.Errorf("marshal FAST inner TGS request body: %w", err)
	}
	innerPAData, outerPAData := splitFASTTGSPAData(request.PAData)
	et, err := crypto.GetEtype(armorKey.KeyType)
	if err != nil {
		return request, fmt.Errorf("select FAST TGS armor encryption type: %w", err)
	}
	checksum, err := et.GetChecksumHash(armorKey.KeyValue, apReqBytes, keyusage.FAST_REQ_CHKSUM)
	if err != nil {
		return request, fmt.Errorf("checksum FAST PA-TGS-REQ: %w", err)
	}
	fastRequest := types.NewKrbFastReq(types.NewKrbFlags(), innerPAData, body)
	plain, err := fastRequest.Marshal()
	if err != nil {
		return request, fmt.Errorf("marshal FAST TGS request: %w", err)
	}
	encrypted, err := crypto.GetEncryptedData(plain, armorKey, keyusage.FAST_ENC, 0)
	if err != nil {
		return request, fmt.Errorf("encrypt FAST TGS request: %w", err)
	}
	fastPA, err := types.NewPAFXFastRequestPAData(types.PAFXFastRequest{ArmoredData: types.KrbFastArmoredReq{
		Armor:       types.KrbFastArmor{ArmorType: 0, ArmorValue: nil}, // Implicit armor from the AP-REQ subkey.
		ReqChecksum: types.Checksum{CksumType: et.GetHashID(), Checksum: checksum},
		EncFastReq:  encrypted,
	}})
	if err != nil {
		return request, fmt.Errorf("marshal FAST TGS PA-FX-FAST request: %w", err)
	}
	outerPAData = append(outerPAData, fastPA)
	request.PAData = outerPAData
	return request, nil
}

func splitFASTTGSPAData(data types.PADataSequence) (types.PADataSequence, types.PADataSequence) {
	inner := make(types.PADataSequence, 0, max(0, len(data)-1))
	outer := make(types.PADataSequence, 0, fastTGSOuterPADataCount)
	for _, pa := range data {
		if pa.PADataType == patype.PA_TGS_REQ {
			outer = append(outer, pa)
		} else {
			inner = append(inner, pa)
		}
	}
	return inner, outer
}

func (state *fastState) setASPreAuth(cl *Client, hint *messages.KRBError, request *messages.ASReq) error {
	if state == nil {
		return errNilFASTState
	}
	if cl == nil || request == nil {
		return errors.New("FAST pre-authentication client and request are required")
	}
	key, et, err := state.asChallengeKey(cl, hint, request.ReqBody.EType)
	if err != nil {
		return err
	}
	if et == 0 {
		et = key.KeyType
	}
	state.replyKey = key
	challenge, err := state.buildASChallenge(cl, key)
	if err != nil {
		return err
	}
	inner, err := fastASPreAuthData(request.PAData, hint)
	if err != nil {
		return err
	}
	inner = append(inner, challenge)
	request.PAData = inner
	state.sentChallenge = true
	cl.settings.preAuthEType = et
	cl.settings.preAuthType = patype.PA_ENCRYPTED_CHALLENGE
	return nil
}

func (state *fastState) asChallengeKey(
	cl *Client,
	hint *messages.KRBError,
	requested []int32,
) (types.EncryptionKey, int32, error) {
	if hint == nil {
		_, key, _, err := firstAvailablePreAuthKey(cl, requested)
		if err != nil {
			return key, 0, fmt.Errorf("get FAST encrypted-challenge key: %w", err)
		}
		return key, state.replyKey.KeyType, nil
	}
	selected, err := preAuthEType(hint, requested)
	if err != nil {
		if len(state.replyKey.KeyValue) == 0 {
			return types.EncryptionKey{}, 0, err
		}
		return state.replyKey, state.replyKey.KeyType, nil
	}
	key, _, err := cl.Key(selected, 0, hint)
	if err != nil {
		return key, 0, fmt.Errorf("get FAST encrypted-challenge key: %w", err)
	}
	return key, selected.GetETypeID(), nil
}

func (state *fastState) buildASChallenge(cl *Client, key types.EncryptionKey) (types.PAData, error) {
	challengeKey, err := crypto.KRBFXCF2(state.armorKey, key, []byte("clientchallengearmor"), []byte("challengelongterm"))
	if err != nil {
		return types.PAData{}, fmt.Errorf("derive FAST encrypted-challenge key: %w", err)
	}
	timestamp, err := types.GetPAEncTSEncAsnMarshalledAt(clientNow().UTC().Add(cl.KDCTimeOffset()))
	if err != nil {
		return types.PAData{}, fmt.Errorf("marshal FAST challenge timestamp: %w", err)
	}
	encrypted, err := crypto.GetEncryptedData(timestamp, challengeKey, keyusage.ENC_CHALLENGE_CLIENT, 0)
	if err != nil {
		return types.PAData{}, fmt.Errorf("encrypt FAST challenge: %w", err)
	}
	challenge, err := types.NewPAEncryptedChallengePAData(types.PAEncryptedChallenge(encrypted))
	if err != nil {
		return types.PAData{}, fmt.Errorf("marshal FAST PA-ENCRYPTED-CHALLENGE: %w", err)
	}
	return challenge, nil
}

func fastASPreAuthData(data types.PADataSequence, hint *messages.KRBError) (types.PADataSequence, error) {
	inner := make(types.PADataSequence, 0, len(data)+1)
	for _, pa := range data {
		switch pa.PADataType {
		case patype.PA_ENC_TIMESTAMP, patype.PA_ENCRYPTED_CHALLENGE, patype.PA_FX_COOKIE:
		default:
			inner = append(inner, pa)
		}
	}
	if hint == nil {
		return inner, nil
	}
	methodData, err := hint.MethodData()
	if err != nil {
		return nil, fmt.Errorf("decode FAST pre-authentication METHOD-DATA: %w", err)
	}
	for _, pa := range methodData {
		if pa.PADataType == patype.PA_FX_COOKIE {
			inner = append(inner, types.PAData{
				PADataType:  pa.PADataType,
				PADataValue: append([]byte(nil), pa.PADataValue...),
			})
		}
	}
	return inner, nil
}

func fastAdvertised(err messages.KRBError) bool {
	var methodData types.PADataSequence
	if unmarshalErr := methodData.Unmarshal(err.EData); unmarshalErr != nil {
		return false
	}
	return methodData.Contains(patype.PA_FX_FAST)
}

func (state *fastState) unwrapResponse(paData types.PADataSequence, nonce int) (types.KrbFastResponse, error) {
	if state == nil {
		return types.KrbFastResponse{}, errNilFASTState
	}
	for i := range paData {
		if paData[i].PADataType != patype.PA_FX_FAST {
			continue
		}
		reply, err := paData[i].GetPAFXFastReply()
		if err != nil {
			return types.KrbFastResponse{}, fmt.Errorf("decode PA-FX-FAST response: %w", err)
		}
		plain, err := crypto.DecryptEncPart(reply.ArmoredData.EncFastRep, state.armorKey, keyusage.FAST_REP)
		if err != nil {
			return types.KrbFastResponse{}, fmt.Errorf("decrypt FAST response: %w", err)
		}
		var response types.KrbFastResponse
		if err := response.Unmarshal(plain); err != nil {
			return response, fmt.Errorf("decode FAST response: %w", err)
		}
		nonce32, convertErr := clientUint32FromInt("FAST nonce", nonce)
		if convertErr != nil {
			return response, convertErr
		}
		if response.Nonce != nonce32 {
			return response, fmt.Errorf("FAST response nonce %d does not match request nonce %d", response.Nonce, nonce)
		}
		return response, nil
	}
	return types.KrbFastResponse{}, errors.New("KDC omitted PA-FX-FAST reply")
}

func (state *fastState) unwrapError(outer messages.KRBError, nonce int) (messages.KRBError, error) {
	if state == nil {
		return messages.KRBError{}, errNilFASTState
	}
	var methodData types.PADataSequence
	if err := methodData.Unmarshal(outer.EData); err != nil {
		return messages.KRBError{}, fmt.Errorf(
			"decode armored KRB-ERROR METHOD-DATA (outer error %d, e-data %d bytes): %w",
			outer.ErrorCode, len(outer.EData), err,
		)
	}
	response, err := state.unwrapResponse(methodData, nonce)
	if err != nil {
		return messages.KRBError{}, err
	}
	var inner messages.KRBError
	found := false
	remaining := make(types.PADataSequence, 0, len(response.PAData))
	for i := range response.PAData {
		if response.PAData[i].PADataType != patype.PA_FX_ERROR {
			remaining = append(remaining, response.PAData[i])
			continue
		}
		encoded, decodeErr := response.PAData[i].GetPAFXError()
		if decodeErr != nil {
			return inner, fmt.Errorf("decode FAST PA-FX-ERROR: %w", decodeErr)
		}
		if ierr := inner.Unmarshal(encoded); ierr != nil {
			return inner, krberror.Errorf(ierr, krberror.EncodingError, "decode FAST inner KRB-ERROR")
		}
		found = true
	}
	if !found {
		return inner, errors.New("FAST error response omitted PA-FX-ERROR")
	}
	inner.EData, err = asn1.Marshal(remaining)
	if err != nil {
		return inner, fmt.Errorf("encode FAST error METHOD-DATA: %w", err)
	}
	return inner, nil
}

func (state *fastState) verifyASReply(
	cl *Client,
	reply *messages.ASRep,
	request messages.ASReq,
	requestBytes []byte,
) error {
	_, err := state.verifyASReplyWithKey(cl, reply, request, requestBytes, nil)
	return err
}

func (state *fastState) verifyASReplyWithKey(
	cl *Client,
	reply *messages.ASRep,
	request messages.ASReq,
	requestBytes []byte,
	deriveReplyKey func(types.PADataSequence) (types.EncryptionKey, error),
) (types.EncryptionKey, error) {
	if state == nil {
		return types.EncryptionKey{}, errNilFASTState
	}
	if cl == nil || reply == nil {
		return types.EncryptionKey{}, errors.New("FAST AS reply client and reply are required")
	}
	response, err := state.unwrapResponse(reply.PAData, request.ReqBody.Nonce)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	if ierr := state.verifyFinished(reply.Ticket, reply.CName, reply.CRealm, response.Finished); ierr != nil {
		return types.EncryptionKey{}, ierr
	}
	if challengeErr := state.verifyASChallengeResponse(response); challengeErr != nil {
		return types.EncryptionKey{}, challengeErr
	}
	replyKey, err := state.asReplyKey(cl, reply.EncPart, response, deriveReplyKey)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	reply.PAData = append(types.PADataSequence(nil), response.PAData...)
	ok, verifyErr := reply.VerifyWithReplyKeyAndRequestBytes(
		cl.Config,
		cl.Credentials,
		request,
		replyKey,
		requestBytes,
	)
	if err := checkFASTReplyVerification("AS-REP", ok, verifyErr); err != nil {
		return types.EncryptionKey{}, err
	}
	cl.syncFASTFinishedTime(response.Finished)
	return replyKey, nil
}

func (state *fastState) verifyASChallengeResponse(response types.KrbFastResponse) error {
	if !state.sentChallenge {
		return nil
	}
	if err := state.verifyKDCChallenge(response.PAData); err != nil {
		return err
	}
	if len(response.StrengthenKey.KeyValue) == 0 {
		return errors.New("FAST encrypted-challenge reply omitted strengthen-key")
	}
	return nil
}

func (state *fastState) asReplyKey(
	cl *Client,
	encPart types.EncryptedData,
	response types.KrbFastResponse,
	deriveReplyKey func(types.PADataSequence) (types.EncryptionKey, error),
) (types.EncryptionKey, error) {
	key, err := state.baseASReplyKey(cl, encPart, response.PAData, deriveReplyKey)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	if len(response.StrengthenKey.KeyValue) == 0 {
		return key, nil
	}
	strengthened, err := crypto.KRBFXCF2(response.StrengthenKey, key, []byte("strengthenkey"), []byte("replykey"))
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("strengthen FAST reply key: %w", err)
	}
	return strengthened, nil
}

func (state *fastState) baseASReplyKey(
	cl *Client,
	encPart types.EncryptedData,
	paData types.PADataSequence,
	deriveReplyKey func(types.PADataSequence) (types.EncryptionKey, error),
) (types.EncryptionKey, error) {
	if deriveReplyKey != nil {
		return deriveReplyKey(paData)
	}
	if len(state.replyKey.KeyValue) != 0 {
		return state.replyKey, nil
	}
	et, err := crypto.GetEtype(encPart.EType)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("select FAST AS reply encryption type: %w", err)
	}
	key, _, err := cl.Key(et, encPart.KVNO, nil)
	return key, err
}

func (state *fastState) verifyTGSReply(cl *Client, reply *messages.TGSRep, request messages.TGSReq) error {
	if state == nil {
		return errNilFASTState
	}
	if cl == nil || reply == nil {
		return errors.New("FAST TGS reply client and reply are required")
	}
	response, err := state.unwrapResponse(reply.PAData, request.ReqBody.Nonce)
	if err != nil {
		return err
	}
	if ierr := state.verifyFinished(reply.Ticket, reply.CName, reply.CRealm, response.Finished); ierr != nil {
		return ierr
	}
	if len(response.StrengthenKey.KeyValue) == 0 {
		return errors.New("FAST TGS reply omitted strengthen-key")
	}
	replyKey, err := crypto.KRBFXCF2(response.StrengthenKey, state.replyKey, []byte("strengthenkey"), []byte("replykey"))
	if err != nil {
		return fmt.Errorf("strengthen FAST TGS reply key: %w", err)
	}
	if err := reply.DecryptEncPartWithKeyUsage(replyKey, keyusage.TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY); err != nil {
		return krberror.Errorf(err, krberror.DecryptingError, "decrypt FAST TGS-REP encrypted part")
	}
	reply.PAData = append(types.PADataSequence(nil), response.PAData...)
	ok, verifyErr := reply.Verify(cl.Config, request)
	if err := checkFASTReplyVerification("TGS-REP", ok, verifyErr); err != nil {
		return err
	}
	cl.syncFASTFinishedTime(response.Finished)
	return nil
}

func (cl *Client) syncFASTFinishedTime(finished types.KrbFastFinished) {
	finishedTime := finished.Timestamp.UTC().Truncate(time.Second).Add(time.Duration(finished.Usec) * time.Microsecond)
	cl.setKDCTimeOffset(finishedTime.Sub(clientNow().UTC()).Truncate(time.Microsecond))
}

func checkFASTReplyVerification(replyType string, ok bool, cause error) error {
	if cause != nil {
		return krberror.Errorf(cause, krberror.KRBMsgError, "verify FAST %s", replyType)
	}
	if !ok {
		return fmt.Errorf("FAST %s verification failed", replyType)
	}
	return nil
}

func (state *fastState) verifyFinished(
	ticket messages.Ticket,
	cname types.PrincipalName,
	realm string,
	finished types.KrbFastFinished,
) error {
	if len(finished.TicketChecksum.Checksum) == 0 {
		return errors.New("FAST reply omitted KrbFastFinished")
	}
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return fmt.Errorf("marshal FAST finished ticket: %w", err)
	}
	checksumType, err := crypto.GetChksumEtype(finished.TicketChecksum.CksumType)
	if err != nil {
		return fmt.Errorf("FAST finished checksum: %w", err)
	}
	if !checksumType.VerifyChecksum(
		state.armorKey.KeyValue, ticketBytes, finished.TicketChecksum.Checksum, keyusage.FAST_FINISHED,
	) {
		return errors.New("FAST finished ticket checksum is invalid")
	}
	if !finished.CName.Equal(cname) || !types.RealmEqual(finished.CRealm, realm) {
		return errors.New("FAST finished client identity does not match KDC-REP")
	}
	return nil
}

func (state *fastState) verifyKDCChallenge(paData types.PADataSequence) error {
	challengeKey, err := crypto.KRBFXCF2(
		state.armorKey, state.replyKey, []byte("kdcchallengearmor"), []byte("challengelongterm"),
	)
	if err != nil {
		return fmt.Errorf("derive KDC FAST challenge key: %w", err)
	}
	for i := range paData {
		if paData[i].PADataType != patype.PA_ENCRYPTED_CHALLENGE {
			continue
		}
		challenge, err := paData[i].GetPAEncryptedChallenge()
		if err != nil {
			return fmt.Errorf("decode KDC FAST PA-ENCRYPTED-CHALLENGE: %w", err)
		}
		plain, err := crypto.DecryptEncPart(types.EncryptedData(challenge), challengeKey, keyusage.ENC_CHALLENGE_KDC)
		if err != nil {
			return fmt.Errorf("decrypt KDC FAST challenge: %w", err)
		}
		var timestamp types.PAEncTSEnc
		if err := timestamp.Unmarshal(plain); err != nil {
			return fmt.Errorf("decode KDC FAST challenge: %w", err)
		}
		return nil
	}
	return errors.New("FAST reply omitted PA-ENCRYPTED-CHALLENGE")
}
