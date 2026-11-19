package client

import (
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/kadmin"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
)

// Kpasswd server response codes.
const (
	KRB5_KPASSWD_SUCCESS             = 0
	KRB5_KPASSWD_MALFORMED           = 1
	KRB5_KPASSWD_HARDERROR           = 2
	KRB5_KPASSWD_AUTHERROR           = 3
	KRB5_KPASSWD_SOFTERROR           = 4
	KRB5_KPASSWD_ACCESSDENIED        = 5
	KRB5_KPASSWD_BAD_VERSION         = 6
	KRB5_KPASSWD_INITIAL_FLAG_NEEDED = 7
)

// ChangePasswd changes the password of the client to the value provided.
// The stored password is updated only after the server confirms the change.
func (cl *Client) ChangePasswd(newPasswd string) (bool, error) {
	ASReq, err := messages.NewASReqForChgPasswd(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return false, fmt.Errorf("build AS-REQ for password change: %w", err)
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return false, err
	}

	msg, key, err := kadmin.ChangePasswdMsg(
		cl.Credentials.CName(),
		cl.Credentials.Domain(),
		newPasswd,
		ASRep.Ticket,
		ASRep.DecryptedEncPart.Key,
	)
	if err != nil {
		return false, krberror.Errorf(err, krberror.KRBMsgError, "build kpasswd request")
	}
	r, err := cl.sendToKPasswd(msg)
	if err != nil {
		return false, err
	}
	if r.IsKRBError {
		return false, r.KRBError
	}
	if err := r.Decrypt(key); err != nil {
		return false, fmt.Errorf("process protected kpasswd reply: %w", err)
	}
	if r.ResultCode != KRB5_KPASSWD_SUCCESS {
		return false, fmt.Errorf("error response from kadmin: code: %d; result: %s", r.ResultCode, r.Result)
	}
	cl.Credentials.WithPassword(newPasswd)
	return true, nil
}

func (cl *Client) sendToKPasswd(msg kadmin.Request) (kadmin.Reply, error) {
	var r kadmin.Reply
	realm := cl.Credentials.Domain()
	_, kps, err := cl.Config.GetKpasswdServers(realm, true)
	if err != nil {
		return r, fmt.Errorf("discover kpasswd servers: %w", err)
	}
	b, err := msg.Marshal()
	if err != nil {
		return r, fmt.Errorf("marshal kpasswd request: %w", err)
	}
	tcp := len(b) > cl.Config.LibDefaults.UDPPreferenceLimit
	rb, err := cl.sendToServers(kps, realm, b, tcp)
	if err != nil {
		return r, err
	}
	if err := r.Unmarshal(rb); err != nil {
		return r, fmt.Errorf("decode kpasswd reply: %w", err)
	}
	return r, nil
}
