package client

import (
	"errors"
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const maxS4UReferrals = 5

type s4uOptions struct {
	forwardable        *bool
	resourceBased      bool
	subjectCertificate []byte
}

// S4UOption configures an S4U2self or S4U2proxy request.
type S4UOption func(*s4uOptions)

// S4UWithForwardable controls the forwardable KDC option on an S4U request.
func S4UWithForwardable(forwardable bool) S4UOption {
	return func(options *s4uOptions) { options.forwardable = &forwardable }
}

// S4UWithResourceBasedDelegation requests resource-based constrained delegation.
func S4UWithResourceBasedDelegation() S4UOption {
	return func(options *s4uOptions) { options.resourceBased = true }
}

// S4UWithCertificate identifies the user with a DER-encoded X.509 certificate.
func S4UWithCertificate(certificate []byte) S4UOption {
	return func(options *s4uOptions) {
		options.subjectCertificate = append([]byte(nil), certificate...)
	}
}

// GetServiceTicketForUser obtains an S4U2self ticket for user to spn.
func (cl *Client) GetServiceTicketForUser(user types.PrincipalName, userRealm, spn string, optionFns ...S4UOption) (messages.Ticket, types.EncryptionKey, error) {
	if userRealm == "" {
		userRealm = cl.Credentials.Realm()
	}
	if ticket, key, ok := cl.GetCachedServiceTicketForUser(user, userRealm, spn); ok {
		return ticket, key, nil
	}
	options := applyS4UOptions(optionFns)
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	tgt, tgtKey, err := cl.s4uRealmTGT(userRealm)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("obtain TGT for S4U2self user realm %s: %w", userRealm, err)
	}
	reply, err := cl.s4u2SelfExchange(service, user, userRealm, userRealm, tgt, tgtKey, options)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	cl.addS4UCacheEntry(user, userRealm, spn, reply)
	return reply.Ticket, reply.DecryptedEncPart.Key, nil
}

// GetServiceTicketOnBehalfOf obtains an S4U2proxy ticket using evidence.
func (cl *Client) GetServiceTicketOnBehalfOf(evidence messages.Ticket, spn string, optionFns ...S4UOption) (messages.Ticket, types.EncryptionKey, error) {
	options := applyS4UOptions(optionFns)
	user, userRealm, identityKnown := cl.s4uIdentityForTicket(evidence)
	if identityKnown {
		if ticket, key, ok := cl.GetCachedServiceTicketForUser(user, userRealm, spn); ok {
			return ticket, key, nil
		}
	}
	target := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn)
	targetRealm := cl.spnRealm(target)
	if targetRealm == "" {
		targetRealm = cl.Credentials.Realm()
	}
	tgt, tgtKey, err := cl.s4uProxyTGT(targetRealm)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("obtain TGT for S4U2proxy target realm %s: %w", targetRealm, err)
	}
	reply, err := cl.s4u2ProxyExchange(target, targetRealm, tgt, tgtKey, evidence, options)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	if identityKnown && (!reply.CName.Equal(user) || !types.RealmEqual(reply.CRealm, userRealm)) {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("S4U2proxy reply identity %s@%s does not match evidence user %s@%s", reply.CName.PrincipalNameString(), reply.CRealm, user.PrincipalNameString(), userRealm)
	}
	if !identityKnown {
		user, userRealm = reply.CName, reply.CRealm
	}
	cl.addS4UCacheEntry(user, userRealm, spn, reply)
	return reply.Ticket, reply.DecryptedEncPart.Key, nil
}

func applyS4UOptions(optionFns []S4UOption) s4uOptions {
	var options s4uOptions
	for _, option := range optionFns {
		if option != nil {
			option(&options)
		}
	}
	return options
}

func (cl *Client) s4uRealmTGT(realm string) (messages.Ticket, types.EncryptionKey, error) {
	homeRealm := cl.Credentials.Realm()
	homeTGT, homeKey, err := cl.sessionTGT(homeRealm)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	if types.RealmEqual(homeRealm, realm) {
		return homeTGT, homeKey, nil
	}
	tgs := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", realm}}
	_, reply, err := cl.TGSREQGenerateAndExchange(tgs, homeRealm, homeTGT, homeKey, false)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}
	return reply.Ticket, reply.DecryptedEncPart.Key, nil
}

func (cl *Client) s4uProxyTGT(targetRealm string) (messages.Ticket, types.EncryptionKey, error) {
	return cl.s4uRealmTGT(targetRealm)
}

func (cl *Client) s4u2SelfExchange(service, user types.PrincipalName, userRealm, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, options s4uOptions) (messages.TGSRep, error) {
	paForUserOnly := false
	subjectCertificate := append([]byte(nil), options.subjectCertificate...)
	for referral := 0; referral <= maxS4UReferrals; referral++ {
		requestOptions := messages.S4U2SelfReqOptions{
			TGSReqOptions:      messages.TGSReqOptions{Forwardable: options.forwardable},
			SubjectCertificate: subjectCertificate,
			PAForUserOnly:      paForUserOnly,
		}
		request, err := messages.NewS4U2SelfTGSReq(cl.Credentials.CName(), kdcRealm, cl.Config, tgt, sessionKey, service, user, userRealm, requestOptions)
		if err != nil {
			return messages.TGSRep{}, fmt.Errorf("build S4U2self request: %w", err)
		}
		reply, err := cl.exchangeS4URequest(request, kdcRealm, sessionKey)
		if err != nil {
			if !paForUserOnly && request.PAData.Contains(patype.PA_S4U_X509_USER) && isKDCError(err, errorcode.KDC_ERR_PADATA_TYPE_NOSUPP) {
				paForUserOnly = true
				continue
			}
			return messages.TGSRep{}, classifyS4UError(err, false)
		}
		replyPAData := types.PADataSequence(reply.PAData)
		if !isReferralReply(reply, request) && !paForUserOnly && request.PAData.Contains(patype.PA_S4U_X509_USER) &&
			options.forwardable != nil && *options.forwardable && !types.IsFlagSet(&reply.DecryptedEncPart.Flags, flags.Forwardable) {
			paForUserOnly = true
			continue
		}
		if request.PAData.Contains(patype.PA_S4U_X509_USER) && replyPAData.Contains(patype.PA_S4U_X509_USER) {
			normalized, err := reply.VerifyS4UX509UserReply(request, sessionKey)
			if err != nil {
				return messages.TGSRep{}, fmt.Errorf("verify PA-S4U-X509-USER reply: %w", err)
			}
			user, userRealm = normalized.CName, normalized.CRealm
			subjectCertificate = nil
		} else if request.PAData.Contains(patype.PA_S4U_X509_USER) {
			return messages.TGSRep{}, fmt.Errorf("S4U2self reply omitted PA-S4U-X509-USER")
		}
		if !isReferralReply(reply, request) {
			if !reply.CName.Equal(user) || !types.RealmEqual(reply.CRealm, userRealm) {
				return messages.TGSRep{}, fmt.Errorf("S4U2self reply identity %s@%s does not match requested user %s@%s", reply.CName.PrincipalNameString(), reply.CRealm, user.PrincipalNameString(), userRealm)
			}
			return reply, nil
		}
		kdcRealm, err = referralRealm(reply.DecryptedEncPart.EncPAData, reply.Ticket.SName.NameString[len(reply.Ticket.SName.NameString)-1])
		if err != nil {
			return messages.TGSRep{}, fmt.Errorf("decode S4U2self referral realm: %w", err)
		}
		tgt, sessionKey = reply.Ticket, reply.DecryptedEncPart.Key
	}
	return messages.TGSRep{}, fmt.Errorf("S4U2self maximum number of referrals exceeded")
}

func (cl *Client) s4u2ProxyExchange(target types.PrincipalName, kdcRealm string, tgt messages.Ticket, sessionKey types.EncryptionKey, evidence messages.Ticket, options s4uOptions) (messages.TGSRep, error) {
	for referral := 0; referral <= maxS4UReferrals; referral++ {
		requestOptions := cl.tgsReqOptions(kdcRealm)
		requestOptions.Forwardable = options.forwardable
		if options.resourceBased {
			requestOptions.PACOptions = append(requestOptions.PACOptions, flags.PACOptionResourceBasedConstrainedDelegation)
		}
		request, err := messages.NewS4U2ProxyTGSReq(cl.Credentials.CName(), kdcRealm, cl.Config, tgt, sessionKey, target, evidence, requestOptions)
		if err != nil {
			return messages.TGSRep{}, fmt.Errorf("build S4U2proxy request: %w", err)
		}
		reply, err := cl.exchangeS4URequest(request, kdcRealm, sessionKey)
		if err != nil {
			return messages.TGSRep{}, classifyS4UError(err, true)
		}
		if !isReferralReply(reply, request) {
			return reply, nil
		}
		kdcRealm, err = referralRealm(reply.DecryptedEncPart.EncPAData, reply.Ticket.SName.NameString[len(reply.Ticket.SName.NameString)-1])
		if err != nil {
			return messages.TGSRep{}, fmt.Errorf("decode S4U2proxy referral realm: %w", err)
		}
		tgt, sessionKey, evidence = reply.Ticket, reply.DecryptedEncPart.Key, reply.Ticket
	}
	return messages.TGSRep{}, fmt.Errorf("S4U2proxy maximum number of referrals exceeded")
}

func (cl *Client) exchangeS4URequest(request messages.TGSReq, realm string, sessionKey types.EncryptionKey) (messages.TGSRep, error) {
	requestBytes, err := request.Marshal()
	if err != nil {
		return messages.TGSRep{}, err
	}
	replyBytes, err := cl.sendKDCRequest(requestBytes, realm)
	if err != nil {
		return messages.TGSRep{}, err
	}
	var reply messages.TGSRep
	if err := reply.Unmarshal(replyBytes); err != nil {
		return reply, err
	}
	if err := reply.DecryptEncPart(sessionKey); err != nil {
		return reply, err
	}
	if ok, err := reply.VerifyS4U(cl.Config, request); !ok {
		return reply, err
	}
	return reply, nil
}

func isReferralReply(reply messages.TGSRep, request messages.TGSReq) bool {
	return len(reply.Ticket.SName.NameString) > 1 && reply.Ticket.SName.NameString[0] == "krbtgt" && !reply.Ticket.SName.Equal(request.ReqBody.SName)
}

func isKDCError(err error, code int32) bool {
	var kdcError messages.KRBError
	return errors.As(err, &kdcError) && kdcError.ErrorCode == code
}

func classifyS4UError(err error, proxy bool) error {
	var kdcError messages.KRBError
	if !errors.As(err, &kdcError) {
		return err
	}
	if proxy && (kdcError.ErrorCode == errorcode.KDC_ERR_BADOPTION || kdcError.ErrorCode == errorcode.KDC_ERR_POLICY) {
		return krberror.NewPolicyError(krberror.ErrDelegationNotPermitted, err)
	}
	if !proxy && (kdcError.ErrorCode == errorcode.KDC_ERR_POLICY || kdcError.ErrorCode == errorcode.KDC_ERR_BADOPTION) {
		return krberror.NewPolicyError(krberror.ErrProtocolTransitionNotPermitted, err)
	}
	return err
}
