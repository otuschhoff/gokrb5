package client

import (
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const fxFastArmorAPRequest int32 = 1

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
			return nil, fmt.Errorf("FAST is required but no armor credentials are configured")
		}
		return nil, nil
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
	return &fastState{active: true}
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
	if len(armor.ticket.SName.NameString) < 2 || !strings.EqualFold(armor.ticket.SName.NameString[0], "krbtgt") || !types.RealmEqual(armor.ticket.SName.NameString[len(armor.ticket.SName.NameString)-1], realm) {
		return fmt.Errorf("FAST armor ticket is not a TGT for realm %s", realm)
	}
	et, err := crypto.GetEtype(armor.key.KeyType)
	if err != nil {
		return fmt.Errorf("FAST armor session key: %w", err)
	}
	auth, err := types.NewAuthenticator(armor.realm, armor.cname)
	if err != nil {
		return fmt.Errorf("create FAST armor authenticator: %w", err)
	}
	now := clientNow().UTC().Add(cl.KDCTimeOffset())
	auth.CTime = now.Truncate(time.Second)
	auth.Cusec = now.Nanosecond() / int(time.Microsecond)
	if err := auth.GenerateSeqNumberAndSubKey(armor.key.KeyType, et.GetKeyByteSize()); err != nil {
		return fmt.Errorf("create FAST armor subkey: %w", err)
	}
	apReq, err := messages.NewAPReq(armor.ticket, armor.key, auth)
	if err != nil {
		return fmt.Errorf("create FAST armor AP-REQ: %w", err)
	}
	armorValue, err := apReq.Marshal()
	if err != nil {
		return fmt.Errorf("marshal FAST armor AP-REQ: %w", err)
	}
	armorKey, err := crypto.KRBFXCF2(auth.SubKey, armor.key, []byte("subkeyarmor"), []byte("ticketarmor"))
	if err != nil {
		return fmt.Errorf("derive FAST armor key: %w", err)
	}
	state.active = true
	state.armor = armor
	state.armorValue = armorValue
	state.armorKey = armorKey
	return nil
}

func (cl *Client) fastArmorForRealm(realm string) (fastArmorCredentials, error) {
	if cl.settings.fastArmor != nil {
		return *cl.settings.fastArmor, nil
	}
	kt := cl.settings.fastArmorKeytab
	if kt == nil {
		return fastArmorCredentials{}, fmt.Errorf("FAST armor credentials are not configured")
	}
	cl.fastArmorMux.Lock()
	defer cl.fastArmorMux.Unlock()
	principals := kt.Principals()
	if len(principals) == 0 {
		return fastArmorCredentials{}, fmt.Errorf("FAST armor keytab contains no principals")
	}
	principal := principals[0]
	for _, candidate := range principals {
		if len(candidate.Components) == 1 && strings.HasSuffix(candidate.Components[0], "$") {
			principal = candidate
			break
		}
	}
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

func (state *fastState) wrapASRequest(request messages.ASReq) (messages.ASReq, error) {
	body, err := request.ReqBody.Marshal()
	if err != nil {
		return request, fmt.Errorf("marshal FAST inner request body: %w", err)
	}
	et, err := crypto.GetEtype(state.armorKey.KeyType)
	if err != nil {
		return request, err
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

func (state *fastState) wrapTGSRequest(request messages.TGSReq, tgt messages.Ticket, sessionKey types.EncryptionKey) (messages.TGSReq, error) {
	subkey, apReqBytes, err := request.SetPADataWithSubkey(tgt, sessionKey)
	if err != nil {
		return request, err
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
	innerPAData := make(types.PADataSequence, 0, len(request.PAData)-1)
	outerPAData := make(types.PADataSequence, 0, 2)
	for _, pa := range request.PAData {
		if pa.PADataType == patype.PA_TGS_REQ {
			outerPAData = append(outerPAData, pa)
		} else {
			innerPAData = append(innerPAData, pa)
		}
	}
	et, err := crypto.GetEtype(armorKey.KeyType)
	if err != nil {
		return request, err
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
		ReqChecksum: types.Checksum{CksumType: et.GetHashID(), Checksum: checksum},
		EncFastReq:  encrypted,
	}})
	if err != nil {
		return request, err
	}
	request.PAData = append(outerPAData, fastPA)
	return request, nil
}

func (state *fastState) setASPreAuth(cl *Client, hint *messages.KRBError, request *messages.ASReq) error {
	var (
		key types.EncryptionKey
		et  = state.replyKey.KeyType
		err error
	)
	if hint == nil {
		_, key, _, err = firstAvailablePreAuthKey(cl, request.ReqBody.EType)
	} else {
		selected, selectErr := preAuthEType(hint, request.ReqBody.EType)
		if selectErr != nil {
			if len(state.replyKey.KeyValue) == 0 {
				return selectErr
			}
			key = state.replyKey
			et = key.KeyType
		} else {
			key, _, err = cl.Key(selected, 0, hint)
			et = selected.GetETypeID()
		}
	}
	if err != nil {
		return fmt.Errorf("get FAST encrypted-challenge key: %w", err)
	}
	if et == 0 {
		et = key.KeyType
	}
	state.replyKey = key
	challengeKey, err := crypto.KRBFXCF2(state.armorKey, key, []byte("clientchallengearmor"), []byte("challengelongterm"))
	if err != nil {
		return fmt.Errorf("derive FAST encrypted-challenge key: %w", err)
	}
	timestamp, err := types.GetPAEncTSEncAsnMarshalledAt(clientNow().UTC().Add(cl.KDCTimeOffset()))
	if err != nil {
		return err
	}
	encrypted, err := crypto.GetEncryptedData(timestamp, challengeKey, keyusage.ENC_CHALLENGE_CLIENT, 0)
	if err != nil {
		return fmt.Errorf("encrypt FAST challenge: %w", err)
	}
	challenge, err := types.NewPAEncryptedChallengePAData(types.PAEncryptedChallenge(encrypted))
	if err != nil {
		return err
	}
	inner := make(types.PADataSequence, 0, len(request.PAData)+1)
	for _, pa := range request.PAData {
		if pa.PADataType != patype.PA_ENC_TIMESTAMP && pa.PADataType != patype.PA_ENCRYPTED_CHALLENGE && pa.PADataType != patype.PA_FX_COOKIE {
			inner = append(inner, pa)
		}
	}
	if hint != nil {
		methodData, methodErr := hint.MethodData()
		if methodErr == nil {
			for _, pa := range methodData {
				if pa.PADataType == patype.PA_FX_COOKIE {
					inner = append(inner, types.PAData{PADataType: pa.PADataType, PADataValue: append([]byte(nil), pa.PADataValue...)})
				}
			}
		}
	}
	request.PAData = append(inner, challenge)
	state.sentChallenge = true
	cl.settings.preAuthEType = et
	cl.settings.preAuthType = patype.PA_ENCRYPTED_CHALLENGE
	return nil
}

func fastAdvertised(err messages.KRBError) bool {
	var methodData types.PADataSequence
	if unmarshalErr := methodData.Unmarshal(err.EData); unmarshalErr != nil {
		return false
	}
	return methodData.Contains(patype.PA_FX_FAST)
}

func (state *fastState) unwrapResponse(paData types.PADataSequence, nonce int) (types.KrbFastResponse, error) {
	for i := range paData {
		if paData[i].PADataType != patype.PA_FX_FAST {
			continue
		}
		reply, err := paData[i].GetPAFXFastReply()
		if err != nil {
			return types.KrbFastResponse{}, err
		}
		plain, err := crypto.DecryptEncPart(reply.ArmoredData.EncFastRep, state.armorKey, keyusage.FAST_REP)
		if err != nil {
			return types.KrbFastResponse{}, fmt.Errorf("decrypt FAST response: %w", err)
		}
		var response types.KrbFastResponse
		if err := response.Unmarshal(plain); err != nil {
			return response, fmt.Errorf("decode FAST response: %w", err)
		}
		if response.Nonce != uint32(nonce) {
			return response, fmt.Errorf("FAST response nonce %d does not match request nonce %d", response.Nonce, nonce)
		}
		return response, nil
	}
	return types.KrbFastResponse{}, fmt.Errorf("KDC omitted PA-FX-FAST reply")
}

func (state *fastState) unwrapError(outer messages.KRBError, nonce int) (messages.KRBError, error) {
	var methodData types.PADataSequence
	if err := methodData.Unmarshal(outer.EData); err != nil {
		return messages.KRBError{}, fmt.Errorf("decode armored KRB-ERROR METHOD-DATA: %w", err)
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
			return inner, decodeErr
		}
		if err := inner.Unmarshal(encoded); err != nil {
			return inner, err
		}
		found = true
	}
	if !found {
		return inner, fmt.Errorf("FAST error response omitted PA-FX-ERROR")
	}
	inner.EData, err = asn1.Marshal(remaining)
	if err != nil {
		return inner, fmt.Errorf("encode FAST error METHOD-DATA: %w", err)
	}
	return inner, nil
}

func (state *fastState) verifyASReply(cl *Client, reply *messages.ASRep, request messages.ASReq) error {
	_, err := state.verifyASReplyWithKey(cl, reply, request, nil)
	return err
}

func (state *fastState) verifyASReplyWithKey(cl *Client, reply *messages.ASRep, request messages.ASReq, deriveReplyKey func(types.PADataSequence) (types.EncryptionKey, error)) (types.EncryptionKey, error) {
	response, err := state.unwrapResponse(reply.PAData, request.ReqBody.Nonce)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	if err := state.verifyFinished(reply.Ticket, reply.CName, reply.CRealm, response.Finished); err != nil {
		return types.EncryptionKey{}, err
	}
	if state.sentChallenge {
		if err := state.verifyKDCChallenge(response.PAData); err != nil {
			return types.EncryptionKey{}, err
		}
		if len(response.StrengthenKey.KeyValue) == 0 {
			return types.EncryptionKey{}, fmt.Errorf("FAST encrypted-challenge reply omitted strengthen-key")
		}
	}
	replyKey := state.replyKey
	if deriveReplyKey != nil {
		replyKey, err = deriveReplyKey(response.PAData)
		if err != nil {
			return types.EncryptionKey{}, err
		}
	} else if len(replyKey.KeyValue) == 0 {
		et, err := crypto.GetEtype(reply.EncPart.EType)
		if err != nil {
			return types.EncryptionKey{}, err
		}
		replyKey, _, err = cl.Key(et, reply.EncPart.KVNO, nil)
		if err != nil {
			return types.EncryptionKey{}, err
		}
	}
	if len(response.StrengthenKey.KeyValue) > 0 {
		replyKey, err = crypto.KRBFXCF2(response.StrengthenKey, replyKey, []byte("strengthenkey"), []byte("replykey"))
		if err != nil {
			return types.EncryptionKey{}, fmt.Errorf("strengthen FAST reply key: %w", err)
		}
	}
	reply.PAData = append(types.PADataSequence(nil), response.PAData...)
	if ok, err := reply.VerifyWithReplyKey(cl.Config, cl.Credentials, request, replyKey); !ok {
		return types.EncryptionKey{}, err
	}
	finishedTime := response.Finished.Timestamp.UTC().Truncate(time.Second).Add(time.Duration(response.Finished.Usec) * time.Microsecond)
	cl.setKDCTimeOffset(finishedTime.Sub(clientNow().UTC()).Truncate(time.Microsecond))
	return replyKey, nil
}

func (state *fastState) verifyTGSReply(cl *Client, reply *messages.TGSRep, request messages.TGSReq) error {
	response, err := state.unwrapResponse(reply.PAData, request.ReqBody.Nonce)
	if err != nil {
		return err
	}
	if err := state.verifyFinished(reply.Ticket, reply.CName, reply.CRealm, response.Finished); err != nil {
		return err
	}
	if len(response.StrengthenKey.KeyValue) == 0 {
		return fmt.Errorf("FAST TGS reply omitted strengthen-key")
	}
	replyKey, err := crypto.KRBFXCF2(response.StrengthenKey, state.replyKey, []byte("strengthenkey"), []byte("replykey"))
	if err != nil {
		return fmt.Errorf("strengthen FAST TGS reply key: %w", err)
	}
	if err := reply.DecryptEncPartWithKeyUsage(replyKey, keyusage.TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY); err != nil {
		return err
	}
	reply.PAData = append(types.PADataSequence(nil), response.PAData...)
	if ok, err := reply.Verify(cl.Config, request); !ok {
		return err
	}
	finishedTime := response.Finished.Timestamp.UTC().Truncate(time.Second).Add(time.Duration(response.Finished.Usec) * time.Microsecond)
	cl.setKDCTimeOffset(finishedTime.Sub(clientNow().UTC()).Truncate(time.Microsecond))
	return nil
}

func (state *fastState) verifyFinished(ticket messages.Ticket, cname types.PrincipalName, realm string, finished types.KrbFastFinished) error {
	if len(finished.TicketChecksum.Checksum) == 0 {
		return fmt.Errorf("FAST reply omitted KrbFastFinished")
	}
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return err
	}
	checksumType, err := crypto.GetChksumEtype(finished.TicketChecksum.CksumType)
	if err != nil {
		return fmt.Errorf("FAST finished checksum: %w", err)
	}
	if !checksumType.VerifyChecksum(state.armorKey.KeyValue, ticketBytes, finished.TicketChecksum.Checksum, keyusage.FAST_FINISHED) {
		return fmt.Errorf("FAST finished ticket checksum is invalid")
	}
	if !finished.CName.Equal(cname) || !types.RealmEqual(finished.CRealm, realm) {
		return fmt.Errorf("FAST finished client identity does not match KDC-REP")
	}
	return nil
}

func (state *fastState) verifyKDCChallenge(paData types.PADataSequence) error {
	challengeKey, err := crypto.KRBFXCF2(state.armorKey, state.replyKey, []byte("kdcchallengearmor"), []byte("challengelongterm"))
	if err != nil {
		return err
	}
	for i := range paData {
		if paData[i].PADataType != patype.PA_ENCRYPTED_CHALLENGE {
			continue
		}
		challenge, err := paData[i].GetPAEncryptedChallenge()
		if err != nil {
			return err
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
	return fmt.Errorf("FAST reply omitted PA-ENCRYPTED-CHALLENGE")
}
