package client

import (
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// TGSREQGenerateAndExchange generates the TGS_REQ and performs a TGS exchange to retrieve a ticket to the specified SPN.
func (cl *Client) TGSREQGenerateAndExchange(spn types.PrincipalName, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, renewal bool) (tgsReq messages.TGSReq, tgsRep messages.TGSRep, err error) {
	options := cl.tgsReqOptions(kdcRealm)
	tgsReq, err = messages.NewTGSReqWithOptions(cl.Credentials.CName(), kdcRealm, cl.Config, tgt, sessionKey, spn, renewal, options)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: failed to generate a new TGS_REQ")
	}
	return cl.TGSExchange(tgsReq, kdcRealm, tgt, sessionKey, 0)
}

// TGSExchange exchanges the provided TGS_REQ with the KDC to retrieve a TGS_REP.
// Referrals are automatically handled.
// The client's cache is updated with the ticket received.
func (cl *Client) TGSExchange(tgsReq messages.TGSReq, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, referral int) (messages.TGSReq, messages.TGSRep, error) {
	var tgsRep messages.TGSRep
	request := tgsReq
	fast := cl.newTGSFASTState(kdcRealm)
	var err error
	if fast != nil {
		request, err = fast.wrapTGSRequest(request, tgt, sessionKey)
		if err != nil {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: failed to build FAST request")
		}
	}
	b, err := request.Marshal()
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to marshal TGS_REQ")
	}
	r, err := cl.sendToKDC(b, kdcRealm)
	if err != nil {
		if kdcErr, ok := err.(messages.KRBError); ok {
			if fast != nil {
				kdcErr, unwrapErr := fast.unwrapError(kdcErr, tgsReq.ReqBody.Nonce)
				if unwrapErr != nil {
					return tgsReq, tgsRep, krberror.Errorf(unwrapErr, krberror.KRBMsgError, "TGS Exchange Error: invalid FAST error response")
				}
				err = kdcErr
			}
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KDCError, "TGS Exchange Error: kerberos error response from KDC when requesting for %s", tgsReq.ReqBody.SName.PrincipalNameString())
		}
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.NetworkingError, "TGS Exchange Error: issue sending TGS_REQ to KDC")
	}
	err = tgsRep.Unmarshal(r)
	if err != nil {
		return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
	}
	if fast != nil {
		if err := fast.verifyTGSReply(cl, &tgsRep, tgsReq); err != nil {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: FAST TGS_REP is not valid")
		}
	} else {
		err = tgsRep.DecryptEncPart(sessionKey)
		if err != nil {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: failed to process the TGS_REP")
		}
		if ok, err := tgsRep.Verify(cl.Config, tgsReq); !ok {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: TGS_REP is not valid")
		}
	}

	if tgsRep.Ticket.SName.NameString[0] == "krbtgt" && !tgsRep.Ticket.SName.Equal(tgsReq.ReqBody.SName) {
		if referral > 5 {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.KRBMsgError, "TGS Exchange Error: maximum number of referrals exceeded")
		}
		// Server referral https://tools.ietf.org/html/rfc6806.html#section-8
		// The TGS Rep contains a TGT for another domain as the service resides in that domain.
		cl.addSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)
		realm, err := referralRealm(tgsRep.DecryptedEncPart.EncPAData, tgsRep.Ticket.SName.NameString[len(tgsRep.Ticket.SName.NameString)-1])
		if err != nil {
			return tgsReq, tgsRep, krberror.Errorf(err, krberror.EncodingError, "TGS Exchange Error: invalid PA-SVR-REFERRAL-INFO")
		}
		options := cl.tgsReqOptions(realm)
		referral++
		if types.IsFlagSet(&tgsReq.ReqBody.KDCOptions, flags.EncTktInSkey) && len(tgsReq.ReqBody.AdditionalTickets) > 0 {
			tgsReq, err = messages.NewUser2UserTGSReqWithOptions(cl.Credentials.CName(), realm, cl.Config, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, tgsReq.ReqBody.SName, tgsReq.Renewal, tgsReq.ReqBody.AdditionalTickets[0], options)
			if err != nil {
				return tgsReq, tgsRep, err
			}
		} else {
			tgsReq, err = messages.NewTGSReqWithOptions(cl.Credentials.CName(), realm, cl.Config, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, tgsReq.ReqBody.SName, tgsReq.Renewal, options)
			if err != nil {
				return tgsReq, tgsRep, err
			}
		}
		return cl.TGSExchange(tgsReq, realm, tgsRep.Ticket, tgsRep.DecryptedEncPart.Key, referral)
	}
	cl.cache.addEntryWithDetails(
		tgsRep.Ticket,
		tgsRep.DecryptedEncPart.AuthTime,
		tgsRep.DecryptedEncPart.StartTime,
		tgsRep.DecryptedEncPart.EndTime,
		tgsRep.DecryptedEncPart.RenewTill,
		tgsRep.DecryptedEncPart.Key,
		tgsRep.DecryptedEncPart.Flags,
		tgsRep.DecryptedEncPart.CAddr,
		nil,
		false,
		nil,
	)
	cl.Log("ticket added to cache for %s (EndTime: %v)", tgsRep.Ticket.SName.PrincipalNameString(), tgsRep.DecryptedEncPart.EndTime)
	return tgsReq, tgsRep, err
}

func (cl *Client) tgsReqOptions(realm string) messages.TGSReqOptions {
	options := messages.TGSReqOptions{}
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
			return "", err
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
	if tkt, skey, ok := cl.GetCachedTicket(spn); ok {
		// Already a valid ticket in the cache
		return tkt, skey, nil
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
func (cl *Client) GetDelegatedCredential(serviceTicket messages.Ticket, serviceSessionKey types.EncryptionKey, addresses types.HostAddresses, force bool) ([]byte, error) {
	if !force {
		entry, ok := cl.cache.getEntry(serviceTicket.SName.PrincipalNameString())
		if !ok || !types.IsFlagSet(&entry.TicketFlags, flags.OKAsDelegate) {
			return nil, fmt.Errorf("service ticket is not trusted for delegation")
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
	sname := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", realm}}
	request, err := messages.NewTGSReqWithOptions(cl.Credentials.CName(), realm, cl.Config, tgt, tgtKey, sname, false, options)
	if err != nil {
		return nil, fmt.Errorf("could not create forwarded-TGT request: %v", err)
	}
	_, reply, err := cl.TGSExchange(request, realm, tgt, tgtKey, 0)
	if err != nil {
		return nil, fmt.Errorf("could not obtain forwarded TGT: %v", err)
	}
	part := reply.DecryptedEncPart
	credential, err := messages.NewKRBCred([]messages.Ticket{reply.Ticket}, []messages.KrbCredInfo{{
		Key: part.Key, PRealm: reply.CRealm, PName: reply.CName, Flags: part.Flags,
		AuthTime: part.AuthTime, StartTime: part.StartTime, EndTime: part.EndTime,
		RenewTill: part.RenewTill, SRealm: part.SRealm, SName: part.SName,
		CAddr: append(types.HostAddresses(nil), part.CAddr...),
	}}, serviceSessionKey)
	if err != nil {
		return nil, fmt.Errorf("could not build delegated KRB_CRED: %v", err)
	}
	return credential.Marshal()
}
