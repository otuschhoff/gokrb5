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

// ASExchange performs an AS exchange for the client to retrieve a TGT.
func (cl *Client) ASExchange(realm string, ASReq messages.ASReq, referral int) (messages.ASRep, error) {
	if ok, err := cl.IsConfigured(); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be performed")
	}

	fast, err := cl.newFASTState(realm, cl.settings.RequireFAST() || cl.settings.AssumePreAuthentication())
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: could not initialize FAST")
	}
	// Set PAData if required
	err = setPAData(cl, nil, &ASReq)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: issue with setting PAData on AS_REQ")
	}
	pkinitEnabled := cl.settings.pkinitOptions != nil && cl.settings.pkinitOptions.Identity != nil
	var pkinitExchange *pkinit.Exchange
	var pkinitOptions pkinit.ExchangeOptions
	var freshnessToken []byte
	if pkinitEnabled {
		pkinitOptions = *cl.settings.pkinitOptions
		pkinitOptions.KDCCertificate.Realm = realm
		if pkinitOptions.KDCCertificate.HTTPClient == nil {
			pkinitOptions.KDCCertificate.HTTPClient = cl.settings.httpClient()
		}
		ASReq.PAData = append(removePAData(ASReq.PAData, patype.PA_ENC_TIMESTAMP, patype.PA_PK_AS_REQ, patype.PA_PK_OCSP_RESPONSE, patype.PA_AS_FRESHNESS), types.PAData{PADataType: patype.PA_AS_FRESHNESS})
		if cl.settings.AssumePreAuthentication() && !pkinitOptions.RequireFreshness {
			pkinitExchange, err = beginPKINITExchange(&ASReq, pkinitOptions, nil)
			if err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: could not build PKINIT request")
			}
		}
	}
	if fast != nil && fast.active && cl.settings.AssumePreAuthentication() {
		if pkinitEnabled {
			// PKINIT supplies the inner pre-authentication mechanism.
		} else if err := fast.setASPreAuth(cl, nil, &ASReq); err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: issue with setting FAST PAData on AS_REQ")
		}
	}

	var ASRep messages.ASRep
	preAuthRetried := false
	skewRetried := false
	preAuthRounds := 0
	pkinitRetried := false
	freshnessRetried := false
	var rb []byte
	var requestBytes []byte
	for {
		request := ASReq
		if fast != nil && fast.active {
			request, err = fast.wrapASRequest(request)
			if err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed building FAST request")
			}
		}
		b, err := request.Marshal()
		if err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ")
		}
		rb, err = cl.sendASRequest(b, realm)
		if err == nil {
			requestBytes = b
			break
		}
		e, ok := err.(messages.KRBError)
		if !ok {
			return messages.ASRep{}, krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
		}
		if fast != nil && fast.active {
			e, err = fast.unwrapError(e, ASReq.ReqBody.Nonce)
			if err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: invalid FAST error response")
			}
		} else if fast != nil && fastAdvertised(e) {
			if err := fast.activate(cl, realm); err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: could not activate FAST")
			}
		}
		if e.ErrorCode == errorcode.KDC_ERR_WRONG_REALM {
			if referral > 5 {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "maximum number of client referrals exceeded")
			}
			return cl.ASExchange(e.CRealm, ASReq, referral+1)
		}
		if pkinitEnabled {
			if isPKINITPreAuthError(e.ErrorCode) {
				token, found, tokenErr := pkinitFreshnessToken(e)
				if tokenErr != nil {
					return messages.ASRep{}, krberror.Errorf(tokenErr, krberror.EncodingError, "AS Exchange Error: invalid PKINIT freshness response")
				}
				if e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED && pkinitExchange != nil && !found {
					// Let clock-skew handling below inspect this otherwise generic error.
				} else if pkinitOptions.RequireFreshness && !found {
					return messages.ASRep{}, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: KDC did not provide required PKINIT freshness token")
				} else if e.ErrorCode == errorcode.KDC_ERR_PREAUTH_EXPIRED {
					if freshnessRetried || !found {
						return messages.ASRep{}, krberror.Errorf(e, krberror.KDCError, "AS Exchange Error: PKINIT freshness retry failed")
					}
					freshnessRetried = true
					freshnessToken = token
				} else {
					freshnessToken = token
				}
				if !(e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED && pkinitExchange != nil && !found) {
					preAuthRounds++
					if preAuthRounds > 5 {
						return messages.ASRep{}, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: maximum PKINIT pre-authentication rounds exceeded")
					}
					pkinitExchange, err = beginPKINITExchange(&ASReq, pkinitOptions, freshnessToken)
					if err != nil {
						return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: could not build PKINIT request")
					}
					continue
				}
			}
			if typed, ok := pkinit.DecodeKRBError(e); ok {
				if !pkinitRetried {
					switch {
					case errors.Is(typed, pkinit.ErrDHParametersNotAccepted):
						group, selectErr := pkinit.SelectDHGroup(typed.DHParameters, pkinitOptions.MinimumDHBits)
						if selectErr != nil {
							return messages.ASRep{}, typed
						}
						pkinitOptions.DHGroup = group
					case errors.Is(typed, pkinit.ErrNoAcceptableKDF):
						pkinitOptions.SupportedKDFs = make([]pkinit.KDFAlgorithmID, 0)
					case errors.Is(typed, pkinit.ErrPublicKeyEncryptionUnsupported) && pkinitOptions.Mode == pkinit.ModeRSA:
						pkinitOptions.Mode = pkinit.ModeDH
					default:
						return messages.ASRep{}, typed
					}
					pkinitRetried = true
					pkinitExchange, err = beginPKINITExchange(&ASReq, pkinitOptions, freshnessToken)
					if err != nil {
						return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: could not rebuild PKINIT request")
					}
					continue
				}
				return messages.ASRep{}, typed
			}
		}
		if !skewRetried && cl.shouldRetryClockSkew(e) {
			cl.setKDCTimeOffset(kdcErrorTime(e).Sub(clientNow().UTC()).Truncate(time.Microsecond))
			cl.settings.assumePreAuthentication = true
			var hint *messages.KRBError
			if e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED && len(e.EData) > 0 {
				hint = &e
			}
			if pkinitEnabled {
				pkinitExchange, err = beginPKINITExchange(&ASReq, pkinitOptions, freshnessToken)
				if err != nil {
					return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed rebuilding PKINIT data after clock skew")
				}
			} else if fast != nil && fast.active {
				if err := fast.setASPreAuth(cl, hint, &ASReq); err != nil {
					return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting FAST PAData after clock skew")
				}
			} else if err := setPAData(cl, hint, &ASReq); err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData after clock skew")
			}
			skewRetried = true
			continue
		}
		if (e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED || e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED || e.ErrorCode == errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED) && (!preAuthRetried || e.ErrorCode == errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED) {
			preAuthRounds++
			if preAuthRounds > 5 {
				return messages.ASRep{}, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: maximum FAST pre-authentication rounds exceeded")
			}
			cl.settings.assumePreAuthentication = true
			if fast != nil && fast.active {
				if err := fast.setASPreAuth(cl, &e, &ASReq); err != nil {
					return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting FAST pre-authentication data")
				}
			} else if err := setPAData(cl, &e, &ASReq); err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData for pre-authentication required")
			}
			preAuthRetried = true
			continue
		}
		return messages.ASRep{}, krberror.Errorf(err, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
	}
	err = ASRep.Unmarshal(rb)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed to process the AS_REP")
	}
	if fast != nil && fast.active {
		if pkinitEnabled {
			if pkinitExchange == nil {
				return messages.ASRep{}, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: KDC returned AS_REP before PKINIT negotiation")
			}
			replyKey, err := fast.verifyASReplyWithKey(cl, &ASRep, ASReq, requestBytes, func(paData types.PADataSequence) (types.EncryptionKey, error) {
				return processPKINITReply(pkinitExchange, paData, ASRep.EncPart.EType)
			})
			if err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: FAST PKINIT AS_REP is not valid")
			}
			cl.setPKINITReplyKey(realm, replyKey)
			return ASRep, nil
		}
		if err := fast.verifyASReply(cl, &ASRep, ASReq, requestBytes); err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: FAST AS_REP is not valid")
		}
		return ASRep, nil
	}
	if cl.settings.RequireFAST() {
		return messages.ASRep{}, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: KDC did not negotiate required FAST")
	}
	if pkinitEnabled {
		if pkinitExchange == nil {
			return messages.ASRep{}, krberror.NewErrorf(krberror.KRBMsgError, "AS Exchange Error: KDC returned AS_REP before PKINIT negotiation")
		}
		replyKey, err := processPKINITReply(pkinitExchange, ASRep.PAData, ASRep.EncPart.EType)
		if err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: invalid PA-PK-AS-REP")
		}
		if ok, err := ASRep.VerifyWithReplyKey(cl.Config, cl.Credentials, ASReq, replyKey); !ok {
			return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: PKINIT AS_REP is not valid")
		}
		cl.setPKINITReplyKey(realm, replyKey)
		return ASRep, nil
	}
	if ok, err := ASRep.Verify(cl.Config, cl.Credentials, ASReq); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid or client password/keytab incorrect")
	}
	return ASRep, nil
}

func (cl *Client) shouldRetryClockSkew(err messages.KRBError) bool {
	if cl.Config.LibDefaults.KDCTimeSync <= 0 || err.STime.IsZero() || err.Susec < 0 || err.Susec >= 1000000 {
		return false
	}
	return err.ErrorCode == errorcode.KRB_AP_ERR_SKEW || err.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED
}

func kdcErrorTime(err messages.KRBError) time.Time {
	return err.STime.UTC().Truncate(time.Second).Add(time.Duration(err.Susec) * time.Microsecond)
}

// setPAData adds pre-authentication data to the AS_REQ.
func setPAData(cl *Client, krberr *messages.KRBError, ASReq *messages.ASReq) error {
	if !cl.settings.DisablePAReqEncPARep() && !ASReq.PAData.Contains(patype.PA_REQ_ENC_PA_REP) {
		pa := types.PAData{PADataType: patype.PA_REQ_ENC_PA_REP}
		ASReq.PAData = append(ASReq.PAData, pa)
	}
	if cl.settings.pkinitOptions != nil && cl.settings.pkinitOptions.Identity != nil {
		return nil
	}
	if cl.settings.AssumePreAuthentication() {
		// Identify the etype to use to encrypt the PA Data
		var et etype.EType
		var err error
		var key types.EncryptionKey
		var kvno int
		if krberr == nil {
			// This is not in response to an error from the KDC. It is preemptive or renewal
			// There is no KRB Error that tells us the etype to use
			et, key, kvno, err = firstAvailablePreAuthKey(cl, ASReq.ReqBody.EType)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting key from credentials")
			}
			cl.settings.preAuthEType = et.GetETypeID()
		} else {
			// Get the etype to use from the PA data in the KRBError e-data
			et, err = preAuthEType(krberr, ASReq.ReqBody.EType)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting etype for pre-auth encryption")
			}
			cl.settings.preAuthEType = et.GetETypeID() // Set the etype that has been defined for potential future use
			key, kvno, err = cl.Key(et, 0, krberr)
			if err != nil {
				return krberror.Errorf(err, krberror.EncryptingError, "error getting key from credentials")
			}
		}
		// Generate the PA data
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
		pa := types.PAData{
			PADataType:  patype.PA_ENC_TIMESTAMP,
			PADataValue: pb,
		}
		filtered := ASReq.PAData[:0]
		for _, existing := range ASReq.PAData {
			if existing.PADataType != patype.PA_ENC_TIMESTAMP {
				filtered = append(filtered, existing)
			}
		}
		ASReq.PAData = append(filtered, pa)
		cl.settings.preAuthType = patype.PA_ENC_TIMESTAMP
	}
	return nil
}

func beginPKINITExchange(request *messages.ASReq, options pkinit.ExchangeOptions, freshness []byte) (*pkinit.Exchange, error) {
	request.PAData = removePAData(request.PAData, patype.PA_PK_AS_REQ, patype.PA_PK_OCSP_RESPONSE, patype.PA_AS_FRESHNESS, patype.PA_ENC_TIMESTAMP)
	options.FreshnessToken = append([]byte(nil), freshness...)
	options.CurrentTime = clientNow().UTC()
	return pkinit.BeginExchange(request, options)
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
		return nil, false, err
	}
	for _, item := range data {
		if item.PADataType == patype.PA_AS_FRESHNESS {
			return append([]byte(nil), item.PADataValue...), true, nil
		}
	}
	return nil, false, nil
}

func processPKINITReply(exchange *pkinit.Exchange, data types.PADataSequence, etype int32) (types.EncryptionKey, error) {
	var value []byte
	for _, item := range data {
		if item.PADataType != patype.PA_PK_AS_REP {
			continue
		}
		if value != nil {
			return types.EncryptionKey{}, fmt.Errorf("KDC returned multiple PA-PK-AS-REP values")
		}
		value = item.PADataValue
	}
	if value == nil {
		return types.EncryptionKey{}, fmt.Errorf("KDC omitted PA-PK-AS-REP")
	}
	result, err := exchange.ProcessReply(value, etype)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	return result.ReplyKey, nil
}

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
		lastErr = fmt.Errorf("no encryption types requested")
	}
	return nil, types.EncryptionKey{}, 0, lastErr
}

// preAuthEType establishes what encryption type to use for pre-authentication from the KRBError returned from the KDC.
func preAuthEType(krberr *messages.KRBError, requested []int32) (etype.EType, error) {
	//RFC 4120 5.2.7.5 covers the preference order of ETYPE-INFO2 and ETYPE-INFO.
	var pas types.PADataSequence
	if err := pas.Unmarshal(krberr.EData); err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "error unmashalling KRBError data")
	}
	requestedSet := make(map[int32]struct{}, len(requested))
	for _, etypeID := range requested {
		requestedSet[etypeID] = struct{}{}
	}
	for _, pa := range pas {
		if pa.PADataType != patype.PA_ETYPE_INFO2 {
			continue
		}
		info, err := pa.GetETypeInfo2()
		if err != nil {
			return nil, krberror.Errorf(err, krberror.EncodingError, "error unmashalling ETYPE-INFO2 data")
		}
		if et, ok := firstRequestedETypeInfo2(info, requestedSet); ok {
			return et, nil
		}
	}
	for _, pa := range pas {
		if pa.PADataType != patype.PA_ETYPE_INFO {
			continue
		}
		info, err := pa.GetETypeInfo()
		if err != nil {
			return nil, krberror.Errorf(err, krberror.EncodingError, "error unmashalling ETYPE-INFO data")
		}
		for _, entry := range info {
			if _, ok := requestedSet[entry.EType]; !ok {
				continue
			}
			et, err := crypto.GetEtype(entry.EType)
			if err == nil {
				return et, nil
			}
		}
	}
	return nil, fmt.Errorf("KDC did not offer a requested supported pre-authentication encryption type")
}

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
