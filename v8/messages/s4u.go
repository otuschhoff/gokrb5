package messages

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc4757"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const s4uAuthPackage = "Kerberos"

// NewPAForUserPAData creates PA-FOR-USER protected with the TGT session key.
func NewPAForUserPAData(
	userName types.PrincipalName, userRealm string, sessionKey types.EncryptionKey,
) (types.PAData, error) {
	data := s4uChecksumData(userName, userRealm, s4uAuthPackage)
	checksum, err := rfc4757.Checksum(sessionKey.KeyValue, keyusage.KERB_NON_KERB_CKSUM_SALT, data)
	if err != nil {
		return types.PAData{}, fmt.Errorf("checksum PA-FOR-USER: %w", err)
	}
	pa, err := types.NewPAForUserPAData(types.PAForUser{
		UserName:    userName,
		UserRealm:   userRealm,
		Cksum:       types.Checksum{CksumType: chksumtype.KERB_CHECKSUM_HMAC_MD5, Checksum: checksum},
		AuthPackage: s4uAuthPackage,
	})
	if err != nil {
		return pa, fmt.Errorf("encode PA-FOR-USER: %w", err)
	}
	return pa, nil
}

func s4uChecksumData(userName types.PrincipalName, userRealm, authPackage string) []byte {
	const nameTypeSize = 4
	b := make([]byte, nameTypeSize, nameTypeSize+len(userRealm)+len(authPackage))
	var nameType bytes.Buffer
	_ = binary.Write(&nameType, binary.LittleEndian, userName.NameType)
	copy(b, nameType.Bytes())
	for _, component := range userName.NameString {
		b = append(b, component...)
	}
	b = append(b, userRealm...)
	b = append(b, authPackage...)
	return b
}

// NewPAS4UX509UserPAData creates PA-S4U-X509-USER using the TGT session key.
func NewPAS4UX509UserPAData(userID types.S4UUserID, sessionKey types.EncryptionKey) (types.PAData, error) {
	userIDBytes, err := userID.Marshal()
	if err != nil {
		return types.PAData{}, fmt.Errorf("marshal S4UUserID: %w", err)
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return types.PAData{}, fmt.Errorf("get S4U session key etype: %w", err)
	}
	checksum, err := etype.GetChecksumHash(sessionKey.KeyValue, userIDBytes, keyusage.PA_S4U_X509_USER_REQUEST)
	if err != nil {
		return types.PAData{}, fmt.Errorf("checksum S4UUserID: %w", err)
	}
	value, err := types.NewPAS4UX509User(userID, types.Checksum{CksumType: etype.GetHashID(), Checksum: checksum})
	if err != nil {
		return types.PAData{}, fmt.Errorf("construct PA-S4U-X509-USER: %w", err)
	}
	pa, err := types.NewPAS4UX509UserPAData(value)
	if err != nil {
		return pa, fmt.Errorf("encode PA-S4U-X509-USER: %w", err)
	}
	return pa, nil
}

func nonceUint32(value int) (uint32, error) {
	if value < 0 || uint64(value) > math.MaxUint32 { // #nosec G115 -- nonnegative branch is bounded before conversion.
		return 0, fmt.Errorf("nonce %d exceeds uint32 range", value)
	}
	return uint32(value), nil // #nosec G115 -- bounded by MaxUint32 above.
}

// VerifyS4UX509UserReply verifies and returns the normalized user identity in a TGS reply.
func (k *TGSRep) VerifyS4UX509UserReply(tgsReq TGSReq, sessionKey types.EncryptionKey) (types.S4UUserID, error) {
	request, err := findS4UX509User(tgsReq.PAData)
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("S4U request: %w", err)
	}
	reply, err := findS4UX509User(k.PAData)
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("S4U reply: %w", err)
	}
	return verifyS4UX509UserReply(request, reply, tgsReq.ReqBody.Nonce, sessionKey)
}

func verifyS4UX509UserReply(
	request, reply types.PAS4UX509User, requestNonce int, sessionKey types.EncryptionKey,
) (types.S4UUserID, error) {
	userID, err := reply.GetUserID()
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("decode S4U reply user ID: %w", err)
	}
	nonce, err := nonceUint32(requestNonce)
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("S4U request nonce: %w", err)
	}
	if userID.Nonce != nonce {
		return types.S4UUserID{},
			fmt.Errorf("S4U reply nonce %d does not match request nonce %d", userID.Nonce, requestNonce)
	}
	userIDBytes, err := userID.Marshal()
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("marshal S4U reply user ID: %w", err)
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("get S4U session key etype: %w", err)
	}
	if reply.Checksum.CksumType != etype.GetHashID() {
		return types.S4UUserID{}, fmt.Errorf(
			"S4U reply checksum type %d does not match required type %d", reply.Checksum.CksumType, etype.GetHashID(),
		)
	}
	usage, err := s4uReplyKeyUsage(request, userID.Options)
	if err != nil {
		return types.S4UUserID{}, err
	}
	if !etype.VerifyChecksum(sessionKey.KeyValue, userIDBytes, reply.Checksum.Checksum, usage) {
		return types.S4UUserID{}, errors.New("S4U reply checksum invalid")
	}
	return userID, nil
}

func s4uReplyKeyUsage(request types.PAS4UX509User, replyOptions asn1.BitString) (uint32, error) {
	requestUserID, err := request.GetUserID()
	if err != nil {
		return 0, fmt.Errorf("decode S4U request user ID: %w", err)
	}
	if !s4uOptionSet(requestUserID.Options, flags.S4UOptionUseReplyKeyUsage) {
		return keyusage.PA_S4U_X509_USER_REQUEST, nil
	}
	if !s4uOptionSet(replyOptions, flags.S4UOptionUseReplyKeyUsage) {
		return 0, errors.New("S4U reply did not acknowledge reply key usage")
	}
	return keyusage.PA_S4U_X509_USER_REPLY, nil
}

func s4uOptionSet(options asn1.BitString, option int) bool {
	return option >= 0 && option/8 < len(options.Bytes) && types.IsFlagSet(&options, option)
}

func findS4UX509User(paData types.PADataSequence) (types.PAS4UX509User, error) {
	for i := range paData {
		if paData[i].PADataType == patype.PA_S4U_X509_USER {
			value, err := paData[i].GetPAS4UX509User()
			if err != nil {
				return value, fmt.Errorf("decode PA-S4U-X509-USER: %w", err)
			}
			return value, nil
		}
	}
	return types.PAS4UX509User{}, errors.New("PA-S4U-X509-USER is missing")
}
