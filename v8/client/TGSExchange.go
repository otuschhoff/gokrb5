package client

import (
	"errors"
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const maxExchangeReferrals = 5

// TGSREQGenerateAndExchange generates a TGS_REQ and exchanges it for a ticket to the specified SPN.
func (cl *Client) TGSREQGenerateAndExchange(
	spn types.PrincipalName,
	kdcRealm string,
	tgt messages.Ticket,
	sessionKey types.EncryptionKey,
	renewal bool,
) (messages.TGSReq, messages.TGSRep, error) {
	var tgsReq messages.TGSReq
	var tgsRep messages.TGSRep
	var err error
	options := cl.tgsReqOptions(kdcRealm)
	tgsReq, err = messages.NewTGSReqWithOptions(
		cl.Credentials.CName(), kdcRealm, cl.Config, tgt, sessionKey, spn, renewal, options,
	)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(
			err, krberror.KRBMsgError, "TGS Exchange Error: failed to generate a new TGS_REQ",
		)
	}
	return cl.TGSExchange(tgsReq, kdcRealm, tgt, sessionKey, 0)
}

// TGSExchange exchanges the provided TGS_REQ with the KDC to retrieve a TGS_REP.
// Referrals are automatically handled.
// The client's cache is updated with the ticket received.
func (cl *Client) TGSExchange(
	tgsReq messages.TGSReq,
	kdcRealm string,
	tgt messages.Ticket,
	sessionKey types.EncryptionKey,
	referral int,
) (messages.TGSReq, messages.TGSRep, error) {
	var tgsRep messages.TGSRep
	request := tgsReq
	fast := cl.newTGSFASTState(kdcRealm)
	var err error
	if fast != nil {
		request, err = fast.wrapTGSRequest(request, tgt, sessionKey)
		if err != nil {
			return tgsReq, tgsRep, krberror.Errorf(
				err, krberror.KRBMsgError, "TGS Exchange Error: failed to build FAST request",
			)
		}
	}
	b, err := request.Marshal()
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to marshal TGS_REQ")
	}
	r, err := cl.sendKDCRequest(b, kdcRealm)
	if err != nil {
		return tgsReq, tgsRep, tgsRequestError(err, fast, tgsReq)
	}
	if err := tgsRep.Unmarshal(r); err != nil {
		return tgsReq, tgsRep, krberror.Errorf(
			err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP",
		)
	}
	if err := cl.verifyTGSExchangeReply(&tgsRep, tgsReq, sessionKey, fast); err != nil {
		return tgsReq, tgsRep, err
	}

	serverName := tgsRep.Ticket.SName
	if len(serverName.NameString) == 0 {
		return tgsReq, tgsRep, newTGSExchangeError("reply ticket has no server principal components")
	}
	if serverName.NameString[0] == tgtServiceName && !serverName.Equal(tgsReq.ReqBody.SName) {
		return cl.followTGSReferral(tgsReq, tgsRep, referral)
	}
	cl.cacheTGSReply(tgsRep)
	return tgsReq, tgsRep, nil
}

func tgsRequestError(cause error, fast *fastState, req messages.TGSReq) error {
	kdcErr, ok := errors.AsType[messages.KRBError](cause)
	if !ok {
		return krberror.Errorf(cause, krberror.NetworkingError, "TGS Exchange Error: issue sending TGS_REQ to KDC")
	}
	if fast != nil {
		unwrapped, err := fast.unwrapError(kdcErr, req.ReqBody.Nonce)
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: invalid FAST error response")
		}
		cause = unwrapped
	}
	return krberror.Errorf(
		cause, krberror.KDCError, "TGS Exchange Error: kerberos error response from KDC when requesting for %s",
		req.ReqBody.SName.PrincipalNameString(),
	)
}

func (cl *Client) verifyTGSExchangeReply(
	rep *messages.TGSRep,
	req messages.TGSReq,
	sessionKey types.EncryptionKey,
	fast *fastState,
) error {
	if fast != nil {
		if err := fast.verifyTGSReply(cl, rep, req); err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: FAST TGS_REP is not valid")
		}
		return nil
	}
	if err := rep.DecryptEncPart(sessionKey); err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
	}
	if ok, err := rep.Verify(cl.Config, req); !ok {
		return krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: TGS_REP is not valid")
	}
	return nil
}

func (cl *Client) cacheTGSReply(reply messages.TGSRep) {
	ticket, part := reply.Ticket, reply.DecryptedEncPart
	cl.cache.addEntryWithDetails(
		ticket,
		part.AuthTime,
		part.StartTime,
		part.EndTime,
		part.RenewTill,
		part.Key,
		part.Flags,
		part.CAddr,
		nil,
		false,
		nil,
	)
	cl.Log("ticket added to cache for %s (EndTime: %v)", ticket.SName.PrincipalNameString(), part.EndTime)
}

func newTGSExchangeError(message string) krberror.Krberror {
	return krberror.NewErrorf(krberror.KRBMsgError, "TGS Exchange Error: %s", message)
}

func (cl *Client) followTGSReferral(
	req messages.TGSReq,
	rep messages.TGSRep,
	count int,
) (messages.TGSReq, messages.TGSRep, error) {
	if count > maxExchangeReferrals {
		return req, rep, newTGSExchangeError("maximum number of referrals exceeded")
	}
	// RFC 6806 section 8: the reply contains the TGT for the next realm.
	part, ticket := rep.DecryptedEncPart, rep.Ticket
	cl.addSession(ticket, part)
	components := ticket.SName.NameString
	realm, err := referralRealm(part.EncPAData, components[len(components)-1])
	if err != nil {
		return req, rep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: invalid PA-SVR-REFERRAL-INFO")
	}
	nextReq, err := cl.newReferralRequest(req, rep, realm)
	if err != nil {
		return nextReq, rep, err
	}
	return cl.TGSExchange(nextReq, realm, ticket, part.Key, count+1)
}

func (cl *Client) newReferralRequest(req messages.TGSReq, rep messages.TGSRep, realm string) (messages.TGSReq, error) {
	options := cl.tgsReqOptions(realm)
	body := req.ReqBody
	if types.IsFlagSet(&body.KDCOptions, flags.EncTktInSkey) && len(body.AdditionalTickets) > 0 {
		next, err := messages.NewUser2UserTGSReqWithOptions(
			cl.Credentials.CName(),
			realm,
			cl.Config,
			rep.Ticket,
			rep.DecryptedEncPart.Key,
			body.SName,
			req.Renewal,
			body.AdditionalTickets[0],
			options,
		)
		if err != nil {
			return next, krberror.Errorf(err, krberror.KRBMsgError, "build user-to-user referral TGS-REQ")
		}
		return next, nil
	}
	next, err := messages.NewTGSReqWithOptions(
		cl.Credentials.CName(),
		realm,
		cl.Config,
		rep.Ticket,
		rep.DecryptedEncPart.Key,
		body.SName,
		req.Renewal,
		options,
	)
	if err != nil {
		return next, krberror.Errorf(err, krberror.KRBMsgError, "build referral TGS-REQ")
	}
	return next, nil
}

func (cl *Client) tgsReqOptions(realm string) messages.TGSReqOptions {
	var options messages.TGSReqOptions
	if session, ok := cl.sessions.get(realm); ok {
		options.SupportedEncTypes = session.supportedEncryptionTypes()
	}
	return options
}

func referralRealm(paData types.PADataSequence, fallback string) (string, error) {
	for i := range paData {
		if paData[i].PADataType != patype.PA_SVR_REFERRAL_INFO {
			continue
		}
		referral, err := paData[i].GetPASvrReferralInfo()
		if err != nil {
			return "", fmt.Errorf("decode referral realm from PA-SVR-REFERRAL-INFO: %w", err)
		}
		if referral.ReferredRealm != "" {
			return referral.ReferredRealm, nil
		}
	}
	return fallback, nil
}

// GetServiceTicket makes a request to get a service ticket for the SPN specified
// SPN format: <SERVICE>/<FQDN> Eg. HTTP/www.example.com
// The ticket will be added to the client's ticket cache
func (cl *Client) GetServiceTicket(spn string) (messages.Ticket, types.EncryptionKey, error) {
	var tkt messages.Ticket
	var skey types.EncryptionKey
	if cachedTkt, cachedSkey, ok := cl.GetCachedTicket(spn); ok {
		// Already a valid ticket in the cache
		return cachedTkt, cachedSkey, nil
	}
	princ := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	realm := cl.spnRealm(princ)

	// if we don't know the SPN's realm, ask the client realm's KDC
	if realm == "" {
		realm = cl.Credentials.Realm()
	}

	tgt, skey, err := cl.sessionTGT(realm)
	if err != nil {
		return tkt, skey, err
	}
	_, tgsRep, err := cl.TGSREQGenerateAndExchange(princ, realm, tgt, skey, false)
	if err != nil {
		return tkt, skey, err
	}
	return tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, nil
}

// GetDelegatedCredential requests a forwarded TGT and wraps it in a KRB-CRED
// encrypted with the service-ticket session key. Unless force is true, the
// service ticket must carry the ok-as-delegate flag.
func (cl *Client) GetDelegatedCredential(
	serviceTicket messages.Ticket,
	serviceSessionKey types.EncryptionKey,
	addresses types.HostAddresses,
	force bool,
) ([]byte, error) {
	if !force {
		entry, ok := cl.cache.getEntry(serviceTicket.SName.PrincipalNameString())
		if !ok || !types.IsFlagSet(&entry.TicketFlags, flags.OKAsDelegate) {
			return nil, errors.New("service ticket is not trusted for delegation")
		}
	}
	realm := cl.Credentials.Realm()
	tgt, tgtKey, err := cl.sessionTGT(realm)
	if err != nil {
		return nil, err
	}
	forwarded := true
	forwardable := true
	addressCopy := append(types.HostAddresses(nil), addresses...)
	options := cl.tgsReqOptions(realm)
	options.Forwarded = &forwarded
	options.Forwardable = &forwardable
	options.Addresses = &addressCopy
	sname := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{tgtServiceName, realm}}
	request, err := messages.NewTGSReqWithOptions(
		cl.Credentials.CName(), realm, cl.Config, tgt, tgtKey, sname, false, options,
	)
	if err != nil {
		return nil, fmt.Errorf("could not create forwarded-TGT request: %w", err)
	}
	_, reply, err := cl.TGSExchange(request, realm, tgt, tgtKey, 0)
	if err != nil {
		return nil, fmt.Errorf("could not obtain forwarded TGT: %w", err)
	}
	part := reply.DecryptedEncPart
	credential, err := messages.NewKRBCred([]messages.Ticket{reply.Ticket}, []messages.KrbCredInfo{{
		Key: part.Key, PRealm: reply.CRealm, PName: reply.CName, Flags: part.Flags,
		AuthTime: part.AuthTime, StartTime: part.StartTime, EndTime: part.EndTime,
		RenewTill: part.RenewTill, SRealm: part.SRealm, SName: part.SName,
		CAddr: append(types.HostAddresses(nil), part.CAddr...),
	}}, serviceSessionKey)
	if err != nil {
		return nil, fmt.Errorf("could not build delegated KRB_CRED: %w", err)
	}
	wire, err := credential.Marshal()
	if err != nil {
		return wire, fmt.Errorf("marshal delegated KRB-CRED: %w", err)
	}
	return wire, nil
}
