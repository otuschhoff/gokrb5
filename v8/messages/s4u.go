package messages

import (
	"encoding/binary"
	"fmt"

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
func NewPAForUserPAData(userName types.PrincipalName, userRealm string, sessionKey types.EncryptionKey) (types.PAData, error) {
	checksum, err := rfc4757.Checksum(sessionKey.KeyValue, keyusage.KERB_NON_KERB_CKSUM_SALT, s4uChecksumData(userName, userRealm, s4uAuthPackage))
	if err != nil {
		return types.PAData{}, err
	}
	return types.NewPAForUserPAData(types.PAForUser{
		UserName:    userName,
		UserRealm:   userRealm,
		Cksum:       types.Checksum{CksumType: chksumtype.KERB_CHECKSUM_HMAC_MD5, Checksum: checksum},
		AuthPackage: s4uAuthPackage,
	})
}

func s4uChecksumData(userName types.PrincipalName, userRealm, authPackage string) []byte {
	b := make([]byte, 4, 4+len(userRealm)+len(authPackage))
	binary.LittleEndian.PutUint32(b, uint32(userName.NameType))
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
		return types.PAData{}, fmt.Errorf("marshal S4UUserID: %v", err)
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return types.PAData{}, fmt.Errorf("get S4U session key etype: %v", err)
	}
	checksum, err := etype.GetChecksumHash(sessionKey.KeyValue, userIDBytes, keyusage.PA_S4U_X509_USER_REQUEST)
	if err != nil {
		return types.PAData{}, fmt.Errorf("checksum S4UUserID: %v", err)
	}
	value, err := types.NewPAS4UX509User(userID, types.Checksum{CksumType: etype.GetHashID(), Checksum: checksum})
	if err != nil {
		return types.PAData{}, err
	}
	return types.NewPAS4UX509UserPAData(value)
}

// VerifyS4UX509UserReply verifies and returns the normalized user identity in a TGS reply.
func (k *TGSRep) VerifyS4UX509UserReply(tgsReq TGSReq, sessionKey types.EncryptionKey) (types.S4UUserID, error) {
	request, err := findS4UX509User(tgsReq.PAData)
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("S4U request: %v", err)
	}
	reply, err := findS4UX509User(k.PAData)
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("S4U reply: %v", err)
	}
	userID, err := reply.GetUserID()
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("decode S4U reply user ID: %v", err)
	}
	if userID.Nonce != uint32(tgsReq.ReqBody.Nonce) {
		return types.S4UUserID{}, fmt.Errorf("S4U reply nonce %d does not match request nonce %d", userID.Nonce, tgsReq.ReqBody.Nonce)
	}
	userIDBytes, err := userID.Marshal()
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("marshal S4U reply user ID: %v", err)
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("get S4U session key etype: %v", err)
	}
	if reply.Checksum.CksumType != etype.GetHashID() {
		return types.S4UUserID{}, fmt.Errorf("S4U reply checksum type %d does not match required type %d", reply.Checksum.CksumType, etype.GetHashID())
	}
	requestUserID, err := request.GetUserID()
	if err != nil {
		return types.S4UUserID{}, fmt.Errorf("decode S4U request user ID: %v", err)
	}
	usage := uint32(keyusage.PA_S4U_X509_USER_REQUEST)
	if s4uOptionSet(requestUserID.Options, flags.S4UOptionUseReplyKeyUsage) {
		if !s4uOptionSet(userID.Options, flags.S4UOptionUseReplyKeyUsage) {
			return types.S4UUserID{}, fmt.Errorf("S4U reply did not acknowledge reply key usage")
		}
		usage = keyusage.PA_S4U_X509_USER_REPLY
	}
	if !etype.VerifyChecksum(sessionKey.KeyValue, userIDBytes, reply.Checksum.Checksum, usage) {
		return types.S4UUserID{}, fmt.Errorf("S4U reply checksum invalid")
	}
	return userID, nil
}

func s4uOptionSet(options asn1.BitString, option int) bool {
	return option >= 0 && option/8 < len(options.Bytes) && types.IsFlagSet(&options, option)
}

func findS4UX509User(paData types.PADataSequence) (types.PAS4UX509User, error) {
	for i := range paData {
		if paData[i].PADataType == patype.PA_S4U_X509_USER {
			return paData[i].GetPAS4UX509User()
		}
	}
	return types.PAS4UX509User{}, fmt.Errorf("PA-S4U-X509-USER is missing")
}
