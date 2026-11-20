package client

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	tgtServiceName      = "krbtgt"
	renewalWindowParts  = 6
	renewalElapsedParts = renewalWindowParts - 1
)

// sessions hold TGTs and are keyed on the realm name
type sessions struct {
	Entries map[string]*session
	mux     sync.RWMutex
}

// JSON return information about the held sessions in a JSON format.
func (s *sessions) JSON() (string, error) {
	s.mux.RLock()
	defer s.mux.RUnlock()
	var js []jsonSession
	keys := make([]string, 0, len(s.Entries))
	for k := range s.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		session := s.Entries[k]
		if session == nil {
			continue
		}
		r, at, et, rt, kt := session.timeDetails()
		j := jsonSession{
			Realm:                r,
			AuthTime:             at,
			EndTime:              et,
			RenewTill:            rt,
			SessionKeyExpiration: kt,
		}
		js = append(js, j)
	}
	b, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode TGT sessions as JSON: %w", err)
	}
	return string(b), nil
}

// destroy erases all sessions
func (s *sessions) destroy() {
	if s == nil {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	for k, e := range s.Entries {
		if e != nil {
			e.destroy()
		}
		delete(s.Entries, k)
	}
}

// update replaces a session with the one provided or adds it as a new one
func (s *sessions) update(sess *session) {
	if s == nil || sess == nil {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	realmKey := strings.ToUpper(sess.realm)
	// if a session already exists for this, cancel its auto renew.
	if previous := s.Entries[realmKey]; previous != nil && previous != sess {
		previous.mux.Lock()
		defer previous.mux.Unlock()
		if previous.cancel != nil {
			previous.cancel <- true
		}
	}
	s.Entries[realmKey] = sess
}

// get returns the session for the realm specified
func (s *sessions) get(realm string) (*session, bool) {
	if s == nil {
		return nil, false
	}
	s.mux.RLock()
	defer s.mux.RUnlock()
	sess := s.Entries[strings.ToUpper(realm)]
	return sess, sess != nil
}

// session holds the TGT details for a realm
type session struct {
	realm                string
	authTime             time.Time
	startTime            time.Time
	endTime              time.Time
	renewTill            time.Time
	tgt                  messages.Ticket
	sessionKey           types.EncryptionKey
	ticketFlags          asn1.BitString
	addresses            []types.HostAddress
	authData             []types.AuthorizationDataEntry
	isSKey               bool
	secondTicket         []byte
	sessionKeyExpiration time.Time
	supportedEncTypes    msflags.SupportedEncTypes
	cancel               chan bool
	mux                  sync.RWMutex
}

// jsonSession is used to enable marshaling some information of a session in a JSON format
type jsonSession struct {
	Realm                string
	AuthTime             time.Time
	EndTime              time.Time
	RenewTill            time.Time
	SessionKeyExpiration time.Time
}

// AddSession adds a session for a realm with a TGT to the client's session cache.
// A goroutine is started to automatically renew the TGT before expiry.
func (cl *Client) addSession(tgt messages.Ticket, dep messages.EncKDCRepPart) {
	if strings.ToLower(tgt.SName.NameString[0]) != tgtServiceName {
		// Not a TGT
		return
	}
	realm := tgt.SName.NameString[len(tgt.SName.NameString)-1]
	supportedEncTypes, err := getSupportedEncTypes(dep.EncPAData)
	if err != nil {
		cl.Log("could not parse PA-SUPPORTED-ENCTYPES for %s: %v", realm, err)
	}
	s := &session{
		realm:                realm,
		authTime:             dep.AuthTime,
		startTime:            dep.StartTime,
		endTime:              dep.EndTime,
		renewTill:            dep.RenewTill,
		tgt:                  tgt,
		sessionKey:           dep.Key,
		ticketFlags:          dep.Flags,
		addresses:            append([]types.HostAddress(nil), dep.CAddr...),
		authData:             nil,
		isSKey:               false,
		secondTicket:         nil,
		sessionKeyExpiration: dep.KeyExpiration,
		supportedEncTypes:    supportedEncTypes,
		cancel:               nil,
		mux:                  sync.RWMutex{},
	}
	cl.sessions.update(s)
	cl.enableAutoSessionRenewal(s)
	cl.Log("TGT session added for %s (EndTime: %v)", realm, dep.EndTime)
}

// update overwrites the session details with those from the TGT and decrypted encPart
func (s *session) update(tgt messages.Ticket, dep messages.EncKDCRepPart) {
	if s == nil {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	s.authTime = dep.AuthTime
	s.startTime = dep.StartTime
	s.endTime = dep.EndTime
	s.renewTill = dep.RenewTill
	s.tgt = tgt
	s.sessionKey = dep.Key
	s.ticketFlags = dep.Flags
	s.addresses = append([]types.HostAddress(nil), dep.CAddr...)
	s.sessionKeyExpiration = dep.KeyExpiration
	s.supportedEncTypes, _ = getSupportedEncTypes(dep.EncPAData)
}

func getSupportedEncTypes(paData types.PADataSequence) (msflags.SupportedEncTypes, error) {
	for i := range paData {
		if paData[i].PADataType != patype.PA_SUPPORTED_ETYPES {
			continue
		}
		value, err := paData[i].GetPASupportedEncTypes()
		return msflags.SupportedEncTypes(value), err
	}
	return 0, nil
}

func (s *session) supportedEncryptionTypes() msflags.SupportedEncTypes {
	if s == nil {
		return 0
	}
	s.mux.RLock()
	defer s.mux.RUnlock()
	return s.supportedEncTypes
}

// destroy will cancel any auto renewal of the session and set the expiration times to the current time
func (s *session) destroy() {
	if s == nil {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.cancel != nil {
		s.cancel <- true
	}
	s.endTime = time.Now().UTC()
	s.renewTill = s.endTime
	s.sessionKeyExpiration = s.endTime
}

// valid informs if the TGT is still within the valid time window
func (s *session) valid() bool {
	if s == nil {
		return false
	}
	s.mux.RLock()
	defer s.mux.RUnlock()
	t := time.Now().UTC()
	if t.Before(s.endTime) && s.authTime.Before(t) {
		return true
	}
	return false
}

// tgtDetails is a thread safe way to get the session's realm, TGT and session key values
func (s *session) tgtDetails() (string, messages.Ticket, types.EncryptionKey) {
	if s == nil {
		var ticket messages.Ticket
		var key types.EncryptionKey
		return "", ticket, key
	}
	s.mux.RLock()
	defer s.mux.RUnlock()
	return s.realm, s.tgt, s.sessionKey
}

// timeDetails is a thread safe way to get the session's validity time values
func (s *session) timeDetails() (string, time.Time, time.Time, time.Time, time.Time) {
	if s == nil {
		return "", time.Time{}, time.Time{}, time.Time{}, time.Time{}
	}
	s.mux.RLock()
	defer s.mux.RUnlock()
	return s.realm, s.authTime, s.endTime, s.renewTill, s.sessionKeyExpiration
}

// enableAutoSessionRenewal turns on the automatic renewal for the client's TGT session.
func (cl *Client) enableAutoSessionRenewal(s *session) {
	s.mux.Lock()
	s.cancel = make(chan bool, 1)
	s.mux.Unlock()
	go cl.autoRenewSession(s)
}

func (cl *Client) autoRenewSession(s *session) {
	for {
		s.mux.RLock()
		w := (s.endTime.Sub(time.Now().UTC()) * renewalElapsedParts) / renewalWindowParts
		s.mux.RUnlock()
		if w < 0 {
			return
		}
		timer := time.NewTimer(w)
		select {
		case <-timer.C:
			renewal, err := cl.refreshSession(s)
			if err != nil {
				cl.Log("error refreshing session: %v", err)
				continue
			}
			if !renewal {
				// The new login started a replacement renewal goroutine.
				return
			}
		case <-s.cancel:
			timer.Stop()
			return
		}
	}
}

// renewTGT renews the client's TGT session.
func (cl *Client) renewTGT(s *session) error {
	realm, tgt, skey := s.tgtDetails()
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{tgtServiceName, realm},
	}
	_, tgsRep, err := cl.TGSREQGenerateAndExchange(spn, cl.Credentials.Domain(), tgt, skey, true)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error renewing TGT for %s", realm)
	}
	s.update(tgsRep.Ticket, tgsRep.DecryptedEncPart)
	cl.sessions.update(s)
	cl.Log("TGT session renewed for %s (EndTime: %v)", realm, tgsRep.DecryptedEncPart.EndTime)
	return nil
}

// Renew renews the TGT session for the client's realm.
func (cl *Client) Renew() error {
	s, ok := cl.sessions.get(cl.Credentials.Domain())
	if !ok {
		return fmt.Errorf("TGT session not found for realm %s", cl.Credentials.Domain())
	}
	return cl.renewTGT(s)
}

// refreshSession updates either through renewal or creating a new login.
// The boolean indicates if the update was a renewal.
func (cl *Client) refreshSession(s *session) (bool, error) {
	s.mux.RLock()
	realm := s.realm
	renewTill := s.renewTill
	s.mux.RUnlock()
	cl.Log("refreshing TGT session for %s", realm)
	if time.Now().UTC().Before(renewTill) {
		err := cl.renewTGT(s)
		return true, err
	}
	err := cl.realmLogin(realm)
	return false, err
}

// ensureValidSession makes sure there is a valid session for the realm
func (cl *Client) ensureValidSession(realm string) error {
	s, ok := cl.sessions.get(realm)
	if ok && s != nil {
		s.mux.RLock()
		d := s.endTime.Sub(s.authTime) / renewalWindowParts
		if s.endTime.Sub(time.Now().UTC()) > d {
			s.mux.RUnlock()
			return nil
		}
		s.mux.RUnlock()
		_, err := cl.refreshSession(s)
		return err
	}
	return cl.realmLogin(realm)
}

// sessionTGTDetails is a thread safe way to get the TGT and session key values for a realm
func (cl *Client) sessionTGT(realm string) (messages.Ticket, types.EncryptionKey, error) {
	var tgt messages.Ticket
	var sessionKey types.EncryptionKey
	var err error
	err = cl.ensureValidSession(realm)
	if err != nil {
		return tgt, sessionKey, err
	}
	s, ok := cl.sessions.get(realm)
	if !ok {
		err = fmt.Errorf("could not find TGT session for %s", realm)
		return tgt, sessionKey, err
	}
	_, tgt, sessionKey = s.tgtDetails()
	return tgt, sessionKey, err
}

// sessionTimes provides the timing information with regards to a session for the realm specified.
func (cl *Client) sessionTimes(realm string) (time.Time, time.Time, time.Time, time.Time, error) {
	var authTime time.Time
	var endTime time.Time
	var renewTime time.Time
	var sessionExp time.Time
	var err error
	s, ok := cl.sessions.get(realm)
	if !ok {
		err = fmt.Errorf("could not find TGT session for %s", realm)
		return authTime, endTime, renewTime, sessionExp, err
	}
	_, authTime, endTime, renewTime, sessionExp = s.timeDetails()
	return authTime, endTime, renewTime, sessionExp, err
}

// spnRealm resolves the realm name of a service principal name
func (cl *Client) spnRealm(spn types.PrincipalName) string {
	return cl.Config.ResolveRealm(spn.NameString[len(spn.NameString)-1])
}
