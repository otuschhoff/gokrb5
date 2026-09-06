package pku2u

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

var pku2uETypes = []int32{
	etypeID.AES256_CTS_HMAC_SHA1_96,
	etypeID.AES128_CTS_HMAC_SHA1_96,
	etypeID.AES256_CTS_HMAC_SHA384_192,
	etypeID.AES128_CTS_HMAC_SHA256_128,
}

func isPKU2UEType(etype int32) bool {
	for _, supported := range pku2uETypes {
		if etype == supported {
			return true
		}
	}
	return false
}

type initiatorASState struct {
	request   messages.ASReq
	exchange  *pkinit.Exchange
	peer      *pkinit.VerifiedSignedData
	peerChain []*x509.Certificate
}

type asResult struct {
	ticket     messages.Ticket
	sessionKey types.EncryptionKey
	ticketKey  types.EncryptionKey
	peer       *pkinit.VerifiedSignedData
	peerChain  []*x509.Certificate
}

func beginASExchange(settings settings, target string) ([]byte, *initiatorASState, error) {
	if settings.identity == nil || settings.identity.Certificate == nil {
		return nil, nil, fmt.Errorf("PKU2U initiator identity is required")
	}
	cname, err := PrincipalFromCertificate(settings.identity.Certificate)
	if err != nil {
		return nil, nil, err
	}
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_HST, target)
	includePAC := false
	cfg := config.New()
	req, err := messages.NewASReqWithOptions(Realm, cfg, cname, sname, messages.ASReqOptions{IncludePAC: &includePAC})
	if err != nil {
		return nil, nil, err
	}
	req.ReqBody.EType = append([]int32(nil), pku2uETypes...)
	state := &initiatorASState{request: req}
	exchange, err := pkinit.BeginExchange(&req, pkinit.ExchangeOptions{
		Identity: settings.identity,
		ValidateIdentity: func(identity *pkinit.Identity, principal types.PrincipalName, realm string) error {
			if realm != Realm {
				return fmt.Errorf("PKU2U identity used with realm %q", realm)
			}
			mapped, err := PrincipalFromCertificate(identity.Certificate)
			if err != nil {
				return err
			}
			if !mapped.Equal(principal) {
				return fmt.Errorf("PKU2U identity does not match client principal")
			}
			return nil
		},
		Mode: pkinit.ModeDH, MinimumDHBits: settings.minimumDHBits, CurrentTime: settings.currentTime(),
		ValidateKDCSigner: func(signed *pkinit.VerifiedSignedData) error {
			chain, err := settings.validatePeer(signed, sname)
			if err != nil {
				return err
			}
			state.peer, state.peerChain = signed, chain
			return nil
		},
	})
	if err != nil {
		return nil, nil, err
	}
	state.exchange = exchange
	encoded, err := req.Marshal()
	state.request = req
	return encoded, state, err
}

func finishASExchange(state *initiatorASState, encoded []byte, settings settings) (*asResult, error) {
	if state == nil || state.exchange == nil {
		return nil, fmt.Errorf("PKU2U AS exchange state is missing")
	}
	var reply messages.ASRep
	if err := reply.Unmarshal(encoded); err != nil {
		return nil, err
	}
	var paValue []byte
	for _, pa := range reply.PAData {
		if pa.PADataType == patype.PA_PK_AS_REP {
			if paValue != nil {
				return nil, fmt.Errorf("PKU2U AS reply contains duplicate PA-PK-AS-REP values")
			}
			paValue = pa.PADataValue
		}
	}
	if paValue == nil {
		return nil, fmt.Errorf("PKU2U AS reply is missing PA-PK-AS-REP")
	}
	pkResult, err := state.exchange.ProcessReply(paValue, reply.EncPart.EType)
	if err != nil {
		return nil, err
	}
	creds := credentials.NewFromPrincipalName(state.request.ReqBody.CName, Realm)
	cfg := config.New()
	cfg.LibDefaults.Clockskew = settings.clockSkew
	verified, err := reply.VerifyWithReplyKey(cfg, creds, state.request, pkResult.ReplyKey)
	if err != nil || !verified {
		return nil, fmt.Errorf("verify PKU2U AS reply: %w", err)
	}
	return &asResult{ticket: reply.Ticket, sessionKey: reply.DecryptedEncPart.Key, peer: state.peer, peerChain: state.peerChain}, nil
}

func acceptASExchange(encoded []byte, settings settings) ([]byte, *asResult, error) {
	var request messages.ASReq
	if err := request.Unmarshal(encoded); err != nil {
		return nil, nil, err
	}
	if request.ReqBody.Realm != Realm {
		return nil, nil, fmt.Errorf("PKU2U AS request uses realm %q", request.ReqBody.Realm)
	}
	if err := certificateIdentifies(settings.identity.Certificate, request.ReqBody.SName); err != nil {
		return nil, nil, fmt.Errorf("PKU2U AS request targets another identity: %w", err)
	}
	pacRequests := 0
	for index := range request.PAData {
		if request.PAData[index].PADataType != patype.PA_PAC_REQUEST {
			continue
		}
		pacRequests++
		pacRequest, err := request.PAData[index].GetKerbPAPACRequest()
		if err != nil || pacRequest.IncludePAC {
			return nil, nil, fmt.Errorf("PKU2U AS request must disable PAC issuance")
		}
	}
	if pacRequests != 1 {
		return nil, nil, fmt.Errorf("PKU2U AS request contains %d PAC requests, want 1", pacRequests)
	}
	var peer *pkinit.VerifiedSignedData
	var peerChain []*x509.Certificate
	pkResult, err := pkinit.AcceptExchange(&request, pkinit.AcceptorOptions{
		Identity: settings.identity, MinimumDHBits: settings.minimumDHBits,
		CurrentTime: settings.currentTime(), ClockSkew: settings.clockSkew,
		ValidateSigner: func(signed *pkinit.VerifiedSignedData) error {
			chain, err := settings.validatePeer(signed, request.ReqBody.CName)
			if err != nil {
				return err
			}
			peer, peerChain = signed, chain
			return nil
		},
	})
	if err != nil {
		return nil, nil, err
	}
	et, err := crypto.GetEtype(pkResult.ReplyKey.KeyType)
	if err != nil {
		return nil, nil, err
	}
	ticketKey, err := types.GenerateEncryptionKey(et)
	if err != nil {
		return nil, nil, err
	}
	now := settings.currentTime().UTC()
	end := now.Add(settings.ticketLifetime)
	if request.ReqBody.Till.Before(end) {
		end = request.ReqBody.Till
	}
	if !end.After(now) {
		return nil, nil, fmt.Errorf("PKU2U AS request ticket lifetime has expired")
	}
	ticketFlags := types.NewKrbFlags()
	types.SetFlag(&ticketFlags, flags.Initial)
	types.SetFlag(&ticketFlags, flags.PreAuthent)
	ticket, sessionKey, err := messages.NewTicketWithKey(
		request.ReqBody.CName, Realm, request.ReqBody.SName, Realm, ticketFlags,
		ticketKey, 0, now, now, end, time.Time{},
	)
	if err != nil {
		return nil, nil, err
	}
	part := messages.EncKDCRepPart{
		Key: sessionKey, Nonce: request.ReqBody.Nonce, Flags: ticketFlags,
		AuthTime: now, StartTime: now, EndTime: end,
		SRealm: Realm, SName: request.ReqBody.SName,
	}
	partDER, err := part.Marshal()
	if err != nil {
		return nil, nil, err
	}
	encryptedPart, err := crypto.GetEncryptedData(partDER, pkResult.ReplyKey, keyusage.AS_REP_ENCPART, 0)
	if err != nil {
		return nil, nil, err
	}
	reply := messages.ASRep{KDCRepFields: messages.KDCRepFields{
		PVNO: iana.PVNO, MsgType: msgtype.KRB_AS_REP,
		PAData: types.PADataSequence{{PADataType: patype.PA_PK_AS_REP, PADataValue: pkResult.ReplyPAData}},
		CRealm: Realm, CName: request.ReqBody.CName, Ticket: ticket, EncPart: encryptedPart,
	}}
	replyDER, err := reply.Marshal()
	return replyDER, &asResult{ticket: ticket, sessionKey: sessionKey, ticketKey: ticketKey, peer: peer, peerChain: peerChain}, err
}
