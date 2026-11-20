package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const maxASPreAuthRounds = 5

// ASExchange performs an AS exchange for the client to retrieve a TGT.
func (cl *Client) ASExchange(realm string, asReq messages.ASReq, referral int) (messages.ASRep, error) {
	if ok, err := cl.IsConfigured(); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be performed")
	}
	var exchange asExchange
	exchange.cl, exchange.realm, exchange.request = cl, realm, asReq
	if err := exchange.prepare(); err != nil {
		return messages.ASRep{}, err
	}
	return exchange.run(referral)
}

type asExchange struct {
	cl               *Client
	realm            string
	request          messages.ASReq
	fast             *fastState
	pkinitEnabled    bool
	pkinitExchange   *pkinit.Exchange
	pkinitOptions    pkinit.ExchangeOptions
	freshnessToken   []byte
	preAuthRetried   bool
	preAuthError     *messages.KRBError
	skewRetried      bool
	timeSynced       bool
	preAuthRounds    int
	pkinitRetried    bool
	freshnessRetried bool
}

func (x *asExchange) prepare() error {
	var err error
	x.fast, err = x.cl.newFASTState(x.realm, x.cl.settings.RequireFAST() || x.cl.settings.AssumePreAuthentication())
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: could not initialize FAST")
	}
	if err := setPAData(x.cl, nil, &x.request); err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: issue with setting PAData on AS_REQ")
	}
	x.pkinitEnabled = x.cl.settings.pkinitOptions != nil && x.cl.settings.pkinitOptions.Identity != nil
	if x.pkinitEnabled {
		return x.preparePKINIT()
	}
	if x.fastActive() && x.cl.settings.AssumePreAuthentication() {
		if err := x.fast.setASPreAuth(x.cl, nil, &x.request); err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: issue with setting FAST PAData on AS_REQ")
		}
	}
	return nil
}

func (x *asExchange) fastActive() bool {
	return x.fast != nil && x.fast.active
}

func (x *asExchange) preparePKINIT() error {
	x.pkinitOptions = *x.cl.settings.pkinitOptions
	x.pkinitOptions.KDCCertificate.Realm = x.realm
	if x.pkinitOptions.KDCCertificate.HTTPClient == nil {
		x.pkinitOptions.KDCCertificate.HTTPClient = x.cl.settings.httpClient()
	}
	x.request.PAData = removePKINITRequestPAData(x.request.PAData)
	x.request.PAData = append(x.request.PAData, types.PAData{PADataType: patype.PA_AS_FRESHNESS, PADataValue: nil})
	if x.cl.settings.AssumePreAuthentication() && !x.pkinitOptions.RequireFreshness {
		return x.beginPKINIT("AS Exchange Error: could not build PKINIT request")
	}
	return nil
}

func (x *asExchange) beginPKINIT(message string) error {
	var err error
	x.pkinitExchange, err = beginPKINITExchange(&x.request, x.pkinitOptions, x.freshnessToken)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "%s", message)
	}
	return nil
}

func (x *asExchange) marshalRequest() ([]byte, error) {
	request := x.request
	if x.fastActive() {
		var err error
		request, err = x.fast.wrapASRequest(request)
		if err != nil {
			return nil, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed building FAST request")
		}
	}
	b, err := request.Marshal()
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ")
	}
	return b, nil
}

func (x *asExchange) run(referral int) (messages.ASRep, error) {
	for {
		b, err := x.marshalRequest()
		if err != nil {
			return messages.ASRep{}, err
		}
		rb, err := x.cl.sendKDCRequest(b, x.realm)
		if err == nil {
			return x.reply(rb, b)
		}
		reply, retry, err := x.handleError(err, referral)
		if err != nil || !retry {
			return reply, err
		}
	}
}

func (x *asExchange) handleError(cause error, referral int) (messages.ASRep, bool, error) {
	e, ok := errors.AsType[messages.KRBError](cause)
	if !ok {
		return messages.ASRep{}, false, krberror.Errorf(
			cause, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC",
		)
	}
	if x.fastActive() {
		inner, err := x.fast.unwrapError(e, x.request.ReqBody.Nonce)
		if err != nil {
			return messages.ASRep{}, false, krberror.Errorf(
				err, krberror.KRBMsgError, "AS Exchange Error: invalid FAST error response",
			)
		}
		// RFC 6113 section 5.4.4: use the authenticated error, not the outer KRB-ERROR.
		e, cause = inner, inner
	} else if err := x.activateAdvertisedFAST(e); err != nil {
		return messages.ASRep{}, false, err
	}
	if !x.timeSynced {
		x.timeSynced = x.cl.syncKDCTime(e)
	}
	if e.ErrorCode == errorcode.KDC_ERR_WRONG_REALM {
		reply, err := x.refer(e, cause, referral)
		return reply, false, err
	}
	retry, err := x.transition(e)
	if retry || err != nil {
		return messages.ASRep{}, retry, err
	}
	return messages.ASRep{}, false, krberror.Errorf(
		cause, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC",
	)
}

func (x *asExchange) activateAdvertisedFAST(e messages.KRBError) error {
	if x.fast == nil || !fastAdvertised(e) {
		return nil
	}
	if err := x.fast.activate(x.cl, x.realm); err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: could not activate FAST")
	}
	return nil
}

func (x *asExchange) refer(e messages.KRBError, cause error, referral int) (messages.ASRep, error) {
	if referral > maxExchangeReferrals {
		return messages.ASRep{}, krberror.Errorf(cause, krberror.KRBMsgError, "maximum number of client referrals exceeded")
	}
	return x.cl.ASExchange(e.CRealm, x.request, referral+1)
}

func (x *asExchange) transition(e messages.KRBError) (bool, error) {
	if x.pkinitEnabled {
		if retry, err := x.retryPKINIT(e); retry || err != nil {
			return retry, err
		}
	}
	if !x.skewRetried && x.cl.shouldRetryClockSkew(e) {
		return true, x.retryClockSkew(e)
	}
	canRetry := !x.preAuthRetried || e.ErrorCode == errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED
	if isASPreAuthError(e.ErrorCode) && canRetry {
		return true, x.retryPreAuth(e)
	}
	return false, nil
}

func isASPreAuthError(code int32) bool {
	return code == errorcode.KDC_ERR_PREAUTH_REQUIRED || code == errorcode.KDC_ERR_PREAUTH_FAILED ||
		code == errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED
}

func newASExchangeError(message string) krberror.Krberror {
	return krberror.Krberror{
		RootCause: krberror.KRBMsgError,
		EText:     []string{krberror.KRBMsgError + ": AS Exchange Error: " + message},
	}
}

func (x *asExchange) retryPKINIT(e messages.KRBError) (bool, error) {
	if isPKINITPreAuthError(e.ErrorCode) {
		if retry, err := x.retryPKINITFreshness(e); retry || err != nil {
			return retry, err
		}
	}
	typed, ok := pkinit.DecodeKRBError(e)
	if !ok {
		return false, nil
	}
	return x.retryPKINITParameters(typed)
}

func (x *asExchange) retryPKINITParameters(typed *pkinit.KRBError) (bool, error) {
	if x.pkinitRetried {
		return false, typed
	}
	if err := x.selectPKINITFallback(typed); err != nil {
		return false, err
	}
	x.pkinitRetried = true
	return true, x.beginPKINIT("AS Exchange Error: could not rebuild PKINIT request")
}

func (x *asExchange) retryPKINITFreshness(e messages.KRBError) (bool, error) {
	token, found, err := pkinitFreshnessToken(e)
	if err != nil {
		return false, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: invalid PKINIT freshness response")
	}
	if e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED && x.pkinitExchange != nil && !found {
		return false, nil
	}
	if x.pkinitOptions.RequireFreshness && !found {
		return false, newASExchangeError("KDC did not provide required PKINIT freshness token")
	}
	if err := x.recordPKINITFreshnessRetry(e, found); err != nil {
		return false, err
	}
	x.freshnessToken = token
	x.preAuthRounds++
	if x.preAuthRounds > maxASPreAuthRounds {
		return false, newASExchangeError("maximum PKINIT pre-authentication rounds exceeded")
	}
	return true, x.beginPKINIT("AS Exchange Error: could not build PKINIT request")
}

func (x *asExchange) recordPKINITFreshnessRetry(e messages.KRBError, found bool) error {
	if e.ErrorCode != errorcode.KDC_ERR_PREAUTH_EXPIRED {
		return nil
	}
	if x.freshnessRetried || !found {
		return krberror.Errorf(e, krberror.KDCError, "AS Exchange Error: PKINIT freshness retry failed")
	}
	x.freshnessRetried = true
	return nil
}

func (x *asExchange) selectPKINITFallback(typed *pkinit.KRBError) error {
	switch {
	case errors.Is(typed, pkinit.ErrDHParametersNotAccepted):
		group, err := pkinit.SelectDHGroup(typed.DHParameters, x.pkinitOptions.MinimumDHBits)
		if err != nil {
			return typed
		}
		x.pkinitOptions.DHGroup = group
	case errors.Is(typed, pkinit.ErrNoAcceptableKDF):
		x.pkinitOptions.SupportedKDFs = make([]pkinit.KDFAlgorithmID, 0)
	case errors.Is(typed, pkinit.ErrPublicKeyEncryptionUnsupported) && x.pkinitOptions.Mode == pkinit.ModeRSA:
		x.pkinitOptions.Mode = pkinit.ModeDH
	default:
		return typed
	}
	return nil
}

func (x *asExchange) retryClockSkew(e messages.KRBError) error {
	x.cl.setKDCTimeOffset(kdcErrorTime(e).Sub(clientNow().UTC()).Truncate(time.Microsecond))
	x.cl.settings.assumePreAuthentication = true
	var hint *messages.KRBError
	if e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED && len(e.EData) > 0 {
		hint = &e
	}
	if err := x.setSkewPreAuth(hint); err != nil {
		return err
	}
	if hint != nil {
		x.preAuthError = hint
	}
	x.skewRetried = true
	return nil
}

func (x *asExchange) setSkewPreAuth(hint *messages.KRBError) error {
	if x.pkinitEnabled {
		return x.beginPKINIT("AS Exchange Error: failed rebuilding PKINIT data after clock skew")
	}
	if x.fastActive() {
		if err := x.fast.setASPreAuth(x.cl, hint, &x.request); err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting FAST PAData after clock skew")
		}
	} else if err := setPAData(x.cl, hint, &x.request); err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData after clock skew")
	}
	return nil
}

func (x *asExchange) retryPreAuth(e messages.KRBError) error {
	x.preAuthRounds++
	if x.preAuthRounds > maxASPreAuthRounds {
		return newASExchangeError("maximum FAST pre-authentication rounds exceeded")
	}
	x.cl.settings.assumePreAuthentication = true
	if x.fastActive() {
		if err := x.fast.setASPreAuth(x.cl, &e, &x.request); err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting FAST pre-authentication data")
		}
	} else if err := setPAData(x.cl, &e, &x.request); err != nil {
		return krberror.Errorf(
			err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required",
		)
	}
	x.preAuthError = &e
	x.preAuthRetried = true
	return nil
}

func (x *asExchange) reply(rb, requestBytes []byte) (messages.ASRep, error) {
	var ASRep messages.ASRep
	if err := ASRep.Unmarshal(rb); err != nil {
		return messages.ASRep{}, krberror.Errorf(
			err, krberror.EncodingError, "AS Exchange Error: failed to process the AS_REP",
		)
	}
	if x.fastActive() {
		return x.fastReply(ASRep, requestBytes)
	}
	if x.cl.settings.RequireFAST() {
		return messages.ASRep{}, newASExchangeError("KDC did not negotiate required FAST")
	}
	if x.pkinitEnabled {
		return x.pkinitReply(ASRep)
	}
	return x.passwordReply(ASRep, requestBytes)
}

func (x *asExchange) fastReply(reply messages.ASRep, requestBytes []byte) (messages.ASRep, error) {
	if !x.pkinitEnabled {
		if err := x.fast.verifyASReply(x.cl, &reply, x.request, requestBytes); err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: FAST AS_REP is not valid")
		}
		return reply, nil
	}
	if x.pkinitExchange == nil {
		return messages.ASRep{}, newASExchangeError("KDC returned AS_REP before PKINIT negotiation")
	}
	deriveKey := func(paData types.PADataSequence) (types.EncryptionKey, error) {
		return processPKINITReply(x.pkinitExchange, paData, reply.EncPart.EType)
	}
	replyKey, err := x.fast.verifyASReplyWithKey(x.cl, &reply, x.request, requestBytes, deriveKey)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(
			err, krberror.KRBMsgError, "AS Exchange Error: FAST PKINIT AS_REP is not valid",
		)
	}
	x.cl.setPKINITReplyKey(x.realm, replyKey)
	return reply, nil
}

func (x *asExchange) pkinitReply(reply messages.ASRep) (messages.ASRep, error) {
	if x.pkinitExchange == nil {
		return messages.ASRep{}, newASExchangeError("KDC returned AS_REP before PKINIT negotiation")
	}
	replyKey, err := processPKINITReply(x.pkinitExchange, reply.PAData, reply.EncPart.EType)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: invalid PA-PK-AS-REP")
	}
	if ok, err := reply.VerifyWithReplyKey(x.cl.Config, x.cl.Credentials, x.request, replyKey); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: PKINIT AS_REP is not valid")
	}
	x.cl.setPKINITReplyKey(x.realm, replyKey)
	return reply, nil
}

func (x *asExchange) passwordReply(reply messages.ASRep, requestBytes []byte) (messages.ASRep, error) {
	if x.preAuthError != nil && x.cl.Credentials.HasPassword() {
		et, err := crypto.GetEtype(reply.EncPart.EType)
		if err != nil {
			return messages.ASRep{}, krberror.Errorf(
				err, krberror.KRBMsgError, "AS Exchange Error: unsupported AS_REP encryption type",
			)
		}
		replyKey, _, err := x.cl.Key(et, reply.EncPart.KVNO, x.preAuthError)
		if err != nil {
			return messages.ASRep{}, krberror.Errorf(
				err, krberror.KRBMsgError, "AS Exchange Error: could not derive AS_REP reply key",
			)
		}
		if ok, err := reply.VerifyWithReplyKeyAndRequestBytes(
			x.cl.Config, x.cl.Credentials, x.request, replyKey, requestBytes,
		); !ok {
			return messages.ASRep{}, krberror.Errorf(
				err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid or client password incorrect",
			)
		}
		return reply, nil
	}
	if ok, err := reply.Verify(x.cl.Config, x.cl.Credentials, x.request); !ok {
		return messages.ASRep{}, krberror.Errorf(
			err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid or client password/keytab incorrect",
		)
	}
	return reply, nil
}

func (cl *Client) shouldRetryClockSkew(err messages.KRBError) bool {
	if cl.Config.LibDefaults.KDCTimeSync <= 0 || err.STime.IsZero() || err.Susec < 0 || err.Susec >= 1000000 {
		return false
	}
	return err.ErrorCode == errorcode.KRB_AP_ERR_SKEW || err.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED
}

func (cl *Client) syncKDCTime(err messages.KRBError) bool {
	if cl.Config.LibDefaults.KDCTimeSync <= 0 || err.STime.IsZero() || err.Susec < 0 || err.Susec >= 1000000 {
		return false
	}
	cl.setKDCTimeOffset(kdcErrorTime(err).Sub(clientNow().UTC()).Truncate(time.Microsecond))
	return true
}

func kdcErrorTime(err messages.KRBError) time.Time {
	return err.STime.UTC().Truncate(time.Second).Add(time.Duration(err.Susec) * time.Microsecond)
}

// setPAData adds pre-authentication data to the AS_REQ.
func setPAData(cl *Client, krberr *messages.KRBError, asReq *messages.ASReq) error {
	if !cl.settings.DisablePAReqEncPARep() && !asReq.PAData.Contains(patype.PA_REQ_ENC_PA_REP) {
		pa := types.PAData{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: nil}
		asReq.PAData = append(asReq.PAData, pa)
	}
	if cl.settings.pkinitOptions != nil && cl.settings.pkinitOptions.Identity != nil {
		return nil
	}
	if !cl.settings.AssumePreAuthentication() {
		return nil
	}
	key, kvno, err := timestampPreAuthKey(cl, krberr, asReq.ReqBody.EType)
	if err != nil {
		return err
	}
	paTSb, err := types.GetPAEncTSEncAsnMarshalledAt(clientNow().UTC().Add(cl.KDCTimeOffset()))
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error creating PAEncTSEnc for Pre-Authentication")
	}
	paEncTS, err := crypto.GetEncryptedData(paTSb, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, kvno)
	if err != nil {
		return krberror.Errorf(err, krberror.EncryptingError, "error encrypting pre-authentication timestamp")
	}
	pb, err := paEncTS.Marshal()
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error marshaling the PAEncTSEnc encrypted data")
	}
	pa := types.PAData{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: pb}
	asReq.PAData = append(removePAData(asReq.PAData, patype.PA_ENC_TIMESTAMP), pa)
	cl.settings.preAuthType = patype.PA_ENC_TIMESTAMP
	return nil
}

func timestampPreAuthKey(cl *Client, hint *messages.KRBError, requested []int32) (types.EncryptionKey, int, error) {
	if hint == nil {
		et, key, kvno, err := firstAvailablePreAuthKey(cl, requested)
		if err != nil {
			return key, kvno, krberror.Errorf(err, krberror.EncryptingError, "error getting key from credentials")
		}
		cl.settings.preAuthEType = et.GetETypeID()
		return key, kvno, nil
	}
	et, err := preAuthEType(hint, requested)
	if err != nil {
		return types.EncryptionKey{}, 0, krberror.Errorf(
			err, krberror.EncryptingError, "error getting etype for pre-auth encryption",
		)
	}
	cl.settings.preAuthEType = et.GetETypeID()
	key, kvno, err := cl.Key(et, 0, hint)
	if err != nil {
		return key, kvno, krberror.Errorf(err, krberror.EncryptingError, "error getting key from credentials")
	}
	return key, kvno, nil
}

func removePKINITRequestPAData(data types.PADataSequence) types.PADataSequence {
	return removePAData(
		data, patype.PA_PK_AS_REQ, patype.PA_PK_OCSP_RESPONSE, patype.PA_AS_FRESHNESS, patype.PA_ENC_TIMESTAMP,
	)
}

func beginPKINITExchange(
	request *messages.ASReq,
	options pkinit.ExchangeOptions,
	freshness []byte,
) (*pkinit.Exchange, error) {
	request.PAData = removePKINITRequestPAData(request.PAData)
	options.FreshnessToken = append([]byte(nil), freshness...)
	options.CurrentTime = clientNow().UTC()
	exchange, err := pkinit.BeginExchange(request, options)
	if err != nil {
		return exchange, krberror.Errorf(err, krberror.KRBMsgError, "initialize PKINIT exchange")
	}
	return exchange, nil
}

func removePAData(data types.PADataSequence, kinds ...int32) types.PADataSequence {
	remove := make(map[int32]struct{}, len(kinds))
	for _, kind := range kinds {
		remove[kind] = struct{}{}
	}
	filtered := data[:0]
	for _, item := range data {
		if _, found := remove[item.PADataType]; !found {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func isPKINITPreAuthError(code int32) bool {
	return code == errorcode.KDC_ERR_PREAUTH_REQUIRED || code == errorcode.KDC_ERR_PREAUTH_FAILED ||
		code == errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED || code == errorcode.KDC_ERR_PREAUTH_EXPIRED
}

func pkinitFreshnessToken(response messages.KRBError) ([]byte, bool, error) {
	if len(response.EData) == 0 {
		return nil, false, nil
	}
	data, err := response.MethodData()
	if err != nil {
		return nil, false, fmt.Errorf("decode PKINIT freshness METHOD-DATA: %w", err)
	}
	for _, item := range data {
		if item.PADataType == patype.PA_AS_FRESHNESS {
			return append([]byte(nil), item.PADataValue...), true, nil
		}
	}
	return nil, false, nil
}

func processPKINITReply(
	exchange *pkinit.Exchange,
	data types.PADataSequence,
	etype int32,
) (types.EncryptionKey, error) {
	var value []byte
	for _, item := range data {
		if item.PADataType != patype.PA_PK_AS_REP {
			continue
		}
		if value != nil {
			return types.EncryptionKey{}, errors.New("KDC returned multiple PA-PK-AS-REP values")
		}
		value = item.PADataValue
	}
	if value == nil {
		return types.EncryptionKey{}, errors.New("KDC omitted PA-PK-AS-REP")
	}
	result, err := exchange.ProcessReply(value, etype)
	if err != nil {
		return types.EncryptionKey{}, krberror.Errorf(err, krberror.KRBMsgError, "process PKINIT reply")
	}
	return result.ReplyKey, nil
}

//nolint:ireturn // Callers use the selected encryption profile and its key together.
func firstAvailablePreAuthKey(cl *Client, requested []int32) (etype.EType, types.EncryptionKey, int, error) {
	var lastErr error
	for _, etypeID := range requested {
		et, err := crypto.GetEtype(etypeID)
		if err != nil {
			lastErr = err
			continue
		}
		key, kvno, err := cl.Key(et, 0, nil)
		if err == nil {
			return et, key, kvno, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no encryption types requested")
	}
	return nil, types.EncryptionKey{}, 0, lastErr
}

// preAuthEType establishes what encryption type to use for pre-authentication from the KRBError returned from the KDC.
//
//nolint:ireturn // Client.Key takes the negotiated encryption profile, not a concrete algorithm.
func preAuthEType(krberr *messages.KRBError, requested []int32) (etype.EType, error) {
	// RFC 4120 5.2.7.5 covers the preference order of ETYPE-INFO2 and ETYPE-INFO.
	var pas types.PADataSequence
	if err := pas.Unmarshal(krberr.EData); err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error unmashalling KRBError data")
	}
	requestedSet := make(map[int32]struct{}, len(requested))
	for _, etypeID := range requested {
		requestedSet[etypeID] = struct{}{}
	}
	et, found, err := preferredETypeInfo2(pas, requestedSet)
	if err != nil || found {
		return et, err
	}
	for _, pa := range pas {
		if pa.PADataType != patype.PA_ETYPE_INFO {
			continue
		}
		info, err := pa.GetETypeInfo()
		if err != nil {
			return nil, krberror.Errorf(err, krberror.EncodingError, "error unmashalling ETYPE-INFO data")
		}
		if et, ok := firstRequestedEType(info, requestedSet); ok {
			return et, nil
		}
	}
	return nil, errors.New("KDC did not offer a requested supported pre-authentication encryption type")
}

//nolint:ireturn // Concrete encryption profiles vary with the negotiated algorithm.
func preferredETypeInfo2(pas types.PADataSequence, requested map[int32]struct{}) (etype.EType, bool, error) {
	for _, pa := range pas {
		if pa.PADataType != patype.PA_ETYPE_INFO2 {
			continue
		}
		info, err := pa.GetETypeInfo2()
		if err != nil {
			return nil, false, krberror.Errorf(err, krberror.EncodingError, "error unmashalling ETYPE-INFO2 data")
		}
		if et, ok := firstRequestedETypeInfo2(info, requested); ok {
			return et, true, nil
		}
	}
	return nil, false, nil
}

//nolint:ireturn // Concrete encryption profiles vary with the negotiated algorithm.
func firstRequestedEType(info types.ETypeInfo, requested map[int32]struct{}) (etype.EType, bool) {
	for _, entry := range info {
		if _, ok := requested[entry.EType]; !ok {
			continue
		}
		et, err := crypto.GetEtype(entry.EType)
		if err == nil {
			return et, true
		}
	}
	return nil, false
}

//nolint:ireturn // Concrete encryption profiles vary with the negotiated algorithm.
func firstRequestedETypeInfo2(info types.ETypeInfo2, requested map[int32]struct{}) (etype.EType, bool) {
	for _, entry := range info {
		if _, ok := requested[entry.EType]; !ok {
			continue
		}
		et, err := crypto.GetEtype(entry.EType)
		if err == nil {
			return et, true
		}
	}
	return nil, false
}
