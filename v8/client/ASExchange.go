package client

import (
	"fmt"
	"time"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// ASExchange performs an AS exchange for the client to retrieve a TGT.
func (cl *Client) ASExchange(realm string, ASReq messages.ASReq, referral int) (messages.ASRep, error) {
	if ok, err := cl.IsConfigured(); !ok {
		return messages.ASRep{}, krberror.Errorf(err, krberror.ConfigError, "AS Exchange cannot be performed")
	}

	// Set PAData if required
	err := setPAData(cl, nil, &ASReq)
	if err != nil {
		return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: issue with setting PAData on AS_REQ")
	}

	var ASRep messages.ASRep
	preAuthRetried := false
	skewRetried := false
	var rb []byte
	for {
		b, err := ASReq.Marshal()
		if err != nil {
			return messages.ASRep{}, krberror.Errorf(err, krberror.EncodingError, "AS Exchange Error: failed marshaling AS_REQ")
		}
		rb, err = cl.sendASRequest(b, realm)
		if err == nil {
			break
		}
		e, ok := err.(messages.KRBError)
		if !ok {
			return messages.ASRep{}, krberror.Errorf(err, krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC")
		}
		if e.ErrorCode == errorcode.KDC_ERR_WRONG_REALM {
			if referral > 5 {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "maximum number of client referrals exceeded")
			}
			return cl.ASExchange(e.CRealm, ASReq, referral+1)
		}
		if !skewRetried && cl.shouldRetryClockSkew(e) {
			cl.setKDCTimeOffset(kdcErrorTime(e).Sub(clientNow().UTC()).Truncate(time.Microsecond))
			cl.settings.assumePreAuthentication = true
			var hint *messages.KRBError
			if e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED && len(e.EData) > 0 {
				hint = &e
			}
			if err := setPAData(cl, hint, &ASReq); err != nil {
				return messages.ASRep{}, krberror.Errorf(err, krberror.KRBMsgError, "AS Exchange Error: failed setting AS_REQ PAData after clock skew")
			}
			skewRetried = true
			continue
		}
		if !preAuthRetried && (e.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED || e.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED) {
			cl.settings.assumePreAuthentication = true
			if err := setPAData(cl, &e, &ASReq); err != nil {
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
