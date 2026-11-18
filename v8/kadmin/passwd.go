// Package kadmin provides Kerberos administration capabilities.
package kadmin

import (
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// ChangePasswdMsg generate a change password request and also return the key needed to decrypt the reply.
func ChangePasswdMsg(cname types.PrincipalName, realm, password string, tkt messages.Ticket, sessionKey types.EncryptionKey) (Request, types.EncryptionKey, error) {
	var
	// Create change password data struct and marshal to bytes
	r Request
	var k types.EncryptionKey
	var err error

	chgpasswd := ChangePasswdData{
		NewPasswd: []byte(password),
		TargName:  cname,
		TargRealm: realm,
	}
	chpwdb, err := chgpasswd.Marshal()
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error marshaling change passwd data")
		return r, k, err
	}

	// Generate authenticator
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
		return r, k, err
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey etype")
		return r, k, err
	}
	err = auth.GenerateSeqNumberAndSubKey(etype.GetETypeID(), etype.GetKeyByteSize())
	if err != nil {
		err = krberror.Errorf(err, krberror.KRBMsgError, "error generating subkey")
		return r, k, err
	}
	k = auth.SubKey

	// Generate AP_REQ
	APreq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		return r, k, err
	}

	// Form the KRBPriv encpart data
	kp := messages.EncKrbPrivPart{
		UserData:       chpwdb,
		Timestamp:      auth.CTime,
		Usec:           auth.Cusec,
		SequenceNumber: auth.SeqNumber,
	}
	kpriv := messages.NewKRBPriv(kp)
	err = kpriv.EncryptEncPart(k)
	if err != nil {
		err = krberror.Errorf(err, krberror.EncryptingError, "error encrypting change passwd data")
		return r, k, err
	}

	r = Request{
		APREQ:   APreq,
		KRBPriv: kpriv,
	}
	return r, k, err
}
