// Package client provides a client library and methods for Kerberos 5 authentication.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pac"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// Client side configuration and state.
type Client struct {
	Credentials   *credentials.Credentials
	Config        *config.Config
	settings      *Settings
	sessions      *sessions
	cache         *Cache
	s4uCache      *Cache
	loginMux      sync.Mutex
	kdcTimeOffset time.Duration
	kdcTimeMux    sync.RWMutex
	fastArmorMux  sync.Mutex
	fastArmorCl   *Client
	pkinitMux     sync.Mutex
	pkinitKeys    map[string]types.EncryptionKey
	pkinitCreds   *pac.CredentialData
	pkinitCredErr error
	sendToKDCFunc func([]byte, string) ([]byte, error)
}

func (cl *Client) setPKINITReplyKey(realm string, key types.EncryptionKey) {
	cl.pkinitMux.Lock()
	defer cl.pkinitMux.Unlock()
	if cl.pkinitKeys == nil {
		cl.pkinitKeys = make(map[string]types.EncryptionKey)
	}
	key.KeyValue = append([]byte(nil), key.KeyValue...)
	cl.pkinitKeys[strings.ToUpper(realm)] = key
}

func (cl *Client) takePKINITReplyKey(realm string) (types.EncryptionKey, bool) {
	cl.pkinitMux.Lock()
	defer cl.pkinitMux.Unlock()
	key, ok := cl.pkinitKeys[strings.ToUpper(realm)]
	delete(cl.pkinitKeys, strings.ToUpper(realm))
	return key, ok
}

// PKINITCredentials returns credentials recovered from PAC_CREDENTIAL_INFO
// after certificate authentication. The returned value is a defensive copy.
func (cl *Client) PKINITCredentials() (pac.CredentialData, error) {
	cl.pkinitMux.Lock()
	defer cl.pkinitMux.Unlock()
	if cl.pkinitCreds == nil {
		if cl.pkinitCredErr != nil {
			return pac.CredentialData{}, cl.pkinitCredErr
		}
		return pac.CredentialData{}, errors.New("PKINIT PAC credentials are not available")
	}
	return clonePKINITCredentialData(*cl.pkinitCreds), nil
}

func clonePKINITCredentialData(data pac.CredentialData) pac.CredentialData {
	copyData := data
	copyData.Credentials = append([]pac.SECPKGSupplementalCred(nil), data.Credentials...)
	for index := range copyData.Credentials {
		copyData.Credentials[index].Credentials = append([]byte(nil), data.Credentials[index].Credentials...)
	}
	return copyData
}

// NewWithPassword creates a new client from a password credential.
// Set the realm to empty string to use the default realm from config.
func NewWithPassword(username, realm, password string, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	if realm == "" && krb5conf != nil {
		realm = krb5conf.LibDefaults.DefaultRealm
	}
	creds := credentials.New(username, realm)
	return &Client{
		Credentials: creds.WithPassword(password),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache:    NewCache(),
		s4uCache: NewCache(),
	}
}

// NewWithKeytab creates a new client from a keytab credential.
func NewWithKeytab(username, realm string, kt *keytab.Keytab, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	if realm == "" && krb5conf != nil {
		realm = krb5conf.LibDefaults.DefaultRealm
	}
	creds := credentials.New(username, realm)
	return &Client{
		Credentials: creds.WithKeytab(kt),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache:    NewCache(),
		s4uCache: NewCache(),
	}
}

// NewFromPrincipalString creates a client from an MIT-style principal string.
// If the principal omits its realm, the configured default realm is used.
func NewFromPrincipalString(princ string, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	parsed, err := keytab.ParsePrincipal(princ)
	if err != nil {
		return nil, fmt.Errorf("invalid client principal: %v", err)
	}
	if parsed.Realm == "" && krb5conf != nil {
		parsed.Realm = krb5conf.LibDefaults.DefaultRealm
	}
	if parsed.Realm == "" {
		return nil, errors.New("client principal does not specify a realm and no default realm is configured")
	}
	return NewFromPrincipalName(types.PrincipalName{
		NameType:   parsed.NameType,
		NameString: append([]string(nil), parsed.Components...),
	}, parsed.Realm, krb5conf, settings...), nil
}

// NewFromPrincipalName creates a client from a typed principal name and realm.
func NewFromPrincipalName(princ types.PrincipalName, realm string, krb5conf *config.Config, settings ...func(*Settings)) *Client {
	if realm == "" && krb5conf != nil {
		realm = krb5conf.LibDefaults.DefaultRealm
	}
	creds := credentials.NewFromPrincipalName(princ, realm)
	return &Client{
		Credentials: creds,
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions:    &sessions{Entries: make(map[string]*session)},
		cache:       NewCache(),
		s4uCache:    NewCache(),
	}
}

// NewFromCCache create a client from a populated client cache.
//
// WARNING: A client created from CCache does not automatically renew TGTs and a failure will occur after the TGT expires.
func NewFromCCache(c *credentials.CCache, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	cl := &Client{
		Credentials: c.GetClientCredentials(),
		Config:      krb5conf,
		settings:    NewSettings(settings...),
		sessions: &sessions{
			Entries: make(map[string]*session),
		},
		cache:    NewCache(),
		s4uCache: NewCache(),
	}
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", c.DefaultPrincipal.Realm},
	}
	entries := c.GetEntries()
	if len(entries) == 0 {
		return cl, errors.New("credential cache contains no credentials")
	}
	tgtCredential, ok := c.GetEntry(spn)
	configCredential := entries[0]
	if ok {
		var tgt messages.Ticket
		if err := tgt.Unmarshal(tgtCredential.Ticket); err != nil {
			return cl, fmt.Errorf("TGT bytes in cache are not valid: %v", err)
		}
		cl.sessions.Entries[c.DefaultPrincipal.Realm] = &session{
			realm:        c.DefaultPrincipal.Realm,
			authTime:     tgtCredential.AuthTime,
			startTime:    tgtCredential.StartTime,
			endTime:      tgtCredential.EndTime,
			renewTill:    tgtCredential.RenewTill,
			tgt:          tgt,
			sessionKey:   tgtCredential.Key,
			ticketFlags:  tgtCredential.TicketFlags,
			addresses:    append([]types.HostAddress(nil), tgtCredential.Addresses...),
			authData:     append([]types.AuthorizationDataEntry(nil), tgtCredential.AuthData...),
			isSKey:       tgtCredential.IsSKey,
			secondTicket: append([]byte(nil), tgtCredential.SecondTicket...),
		}
		configCredential = tgtCredential
	}
	if offset, ok := c.KDCTimeOffset(); ok {
		cl.setKDCTimeOffset(offset)
	}
	configPrincipal := configCredential.Server.PrincipalName.PrincipalNameString() + "@" + configCredential.Server.Realm
	if value, ok := c.GetConfig("pa_type", configPrincipal); ok {
		paType, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return cl, fmt.Errorf("invalid pa_type credential cache config value %q: %v", value, err)
		}
		cl.settings.preAuthType = int32(paType)
	}
	for _, cred := range entries {
		if cred == tgtCredential {
			continue
		}
		var tkt messages.Ticket
		if err := tkt.Unmarshal(cred.Ticket); err != nil {
			return cl, fmt.Errorf("cache entry ticket bytes are not valid: %v", err)
		}
		cl.cache.addEntryWithDetails(
			tkt,
			cred.AuthTime,
			cred.StartTime,
			cred.EndTime,
			cred.RenewTill,
			cred.Key,
			cred.TicketFlags,
			cred.Addresses,
			cred.AuthData,
			cred.IsSKey,
			cred.SecondTicket,
		)
	}
	return cl, nil
}

// KDCTimeOffset returns the time offset learned from the KDC.
func (cl *Client) KDCTimeOffset() time.Duration {
	cl.kdcTimeMux.RLock()
	defer cl.kdcTimeMux.RUnlock()
	return cl.kdcTimeOffset
}

func (cl *Client) setKDCTimeOffset(offset time.Duration) {
	cl.kdcTimeMux.Lock()
	cl.kdcTimeOffset = offset
	cl.kdcTimeMux.Unlock()
}

func (cl *Client) sendASRequest(request []byte, realm string) ([]byte, error) {
	if cl.sendToKDCFunc != nil {
		return cl.sendToKDCFunc(request, realm)
	}
	return cl.sendToKDC(request, realm)
}

// Key returns the client's encryption key for the specified encryption type and its kvno (kvno of zero will find latest).
// The key can be retrieved either from the keytab or generated from the client's password.
// If the client has both a keytab and a password defined the keytab is favoured as the source for the key
// A KRBError can be passed in the event the KDC returns one of type KDC_ERR_PREAUTH_REQUIRED and is required to derive
// the key for pre-authentication from the client's password. If a KRBError is not available, pass nil to this argument.
func (cl *Client) Key(etype etype.EType, kvno int, krberr *messages.KRBError) (types.EncryptionKey, int, error) {
	if cl.Credentials.HasKeytab() && etype != nil {
		return cl.Credentials.Keytab().GetEncryptionKey(cl.Credentials.CName(), cl.Credentials.Domain(), kvno, etype.GetETypeID())
	} else if cl.Credentials.HasPassword() {
		if krberr != nil && (krberr.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED || krberr.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED) {
			var pas types.PADataSequence
			err := pas.Unmarshal(krberr.EData)
			if err != nil {
				return types.EncryptionKey{}, 0, fmt.Errorf("could not get PAData from KRBError to generate key from password: %v", err)
			}
			key, _, err := crypto.GetKeyFromPassword(cl.Credentials.Password(), krberr.CName, krberr.CRealm, etype.GetETypeID(), pas)
			return key, 0, err
		}
		key, _, err := crypto.GetKeyFromPassword(cl.Credentials.Password(), cl.Credentials.CName(), cl.Credentials.Domain(), etype.GetETypeID(), types.PADataSequence{})
		return key, 0, err
	}
	return types.EncryptionKey{}, 0, errors.New("credential has neither keytab or password to generate key")
}

// IsConfigured indicates if the client has the values required set.
func (cl *Client) IsConfigured() (bool, error) {
	if cl.Config == nil {
		return false, errors.New("client does not have a Kerberos configuration")
	}
	if cl.Credentials.UserName() == "" {
		return false, errors.New("client does not have a username")
	}
	if cl.Credentials.Domain() == "" {
		if cl.Config.LibDefaults.DefaultRealm == "" {
			return false, errors.New("client does not have a defined realm")
		}
		cl.Credentials.SetDomain(cl.Config.LibDefaults.DefaultRealm)
	}
	// Client needs to have either a password, keytab or a session already (later when loading from CCache)
	if !cl.Credentials.HasPassword() && !cl.Credentials.HasKeytab() && (cl.settings.pkinitOptions == nil || cl.settings.pkinitOptions.Identity == nil) {
		authTime, _, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
		if err != nil || authTime.IsZero() {
			return false, errors.New("client has neither a keytab nor a password set and no session")
		}
	}
	if !cl.Config.LibDefaults.DNSLookupKDC {
		for _, r := range cl.Config.Realms {
			if types.RealmEqual(r.Realm, cl.Credentials.Domain()) {
				if len(r.KDC) > 0 {
					return true, nil
				}
				return false, errors.New("client krb5 config does not have any defined KDCs for the default realm")
			}
		}
	}
	return true, nil
}

// Login the client with the KDC via an AS exchange.
func (cl *Client) Login() error {
	return cl.LoginWithOptions(messages.ASReqOptions{})
}

// LoginWithOptions logs the client in with per-request AS options.
func (cl *Client) LoginWithOptions(options messages.ASReqOptions) error {
	cl.loginMux.Lock()
	defer cl.loginMux.Unlock()

	if ok, err := cl.IsConfigured(); !ok {
		return err
	}
	pkinitConfigured := cl.settings.pkinitOptions != nil && cl.settings.pkinitOptions.Identity != nil
	if !cl.Credentials.HasPassword() && !cl.Credentials.HasKeytab() && !pkinitConfigured {
		_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
		if err != nil {
			return krberror.Errorf(err, krberror.KRBMsgError, "no user credentials available and error getting any existing session")
		}
		if time.Now().UTC().After(endTime) {
			return krberror.New(krberror.KRBMsgError, "cannot login, no user credentials available and no valid existing session")
		}
		// no credentials but there is a session with tgt already
		return nil
	}
	ASReq, err := cl.newASReqWithOptions(options)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error generating new AS_REQ")
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return err
	}
	if len(ASRep.Ticket.SName.NameString) > 0 && strings.EqualFold(ASRep.Ticket.SName.NameString[0], "krbtgt") {
		cl.addSession(ASRep.Ticket, ASRep.DecryptedEncPart)
		if replyKey, ok := cl.takePKINITReplyKey(cl.Credentials.Domain()); ok {
			cl.pkinitMux.Lock()
			cl.pkinitCreds = nil
			cl.pkinitCredErr = nil
			cl.pkinitMux.Unlock()
			if err := cl.retrievePKINITCredentials(ASRep.Ticket, ASRep.DecryptedEncPart, replyKey); err != nil {
				cl.pkinitMux.Lock()
				cl.pkinitCredErr = err
				cl.pkinitMux.Unlock()
				cl.Log("could not retrieve PKINIT PAC credentials: %v", err)
			}
		}
	} else {
		cl.cache.addEntryWithDetails(
			ASRep.Ticket,
			ASRep.DecryptedEncPart.AuthTime,
			ASRep.DecryptedEncPart.StartTime,
			ASRep.DecryptedEncPart.EndTime,
			ASRep.DecryptedEncPart.RenewTill,
			ASRep.DecryptedEncPart.Key,
			ASRep.DecryptedEncPart.Flags,
			ASRep.DecryptedEncPart.CAddr,
			nil,
			false,
			nil,
		)
	}
	return nil
}

func (cl *Client) retrievePKINITCredentials(tgt messages.Ticket, reply messages.EncKDCRepPart, replyKey types.EncryptionKey) error {
	request, err := messages.NewUser2UserTGSReq(cl.Credentials.CName(), cl.Credentials.Domain(), cl.Config, tgt, reply.Key, cl.Credentials.CName(), false, tgt)
	if err != nil {
		return fmt.Errorf("build PKINIT credential U2U request: %w", err)
	}
	_, response, err := cl.TGSExchange(request, cl.Credentials.Domain(), tgt, reply.Key, 0)
	if err != nil {
		return fmt.Errorf("request PKINIT credential U2U ticket: %w", err)
	}
	if err := response.Ticket.Decrypt(reply.Key); err != nil {
		return fmt.Errorf("decrypt PKINIT credential U2U ticket: %w", err)
	}
	entries, err := response.Ticket.DecryptedEncPart.AuthorizationData.EntriesOfType(adtype.ADWin2KPAC)
	if err != nil {
		return fmt.Errorf("find PKINIT credential PAC: %w", err)
	}
	if len(entries) != 1 {
		return fmt.Errorf("PKINIT credential U2U ticket contains %d PAC values", len(entries))
	}
	var parsed pac.PACType
	if err := parsed.Unmarshal(entries[0].ADData); err != nil {
		return fmt.Errorf("decode PKINIT credential PAC: %w", err)
	}
	logger := cl.settings.Logger()
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	if err := parsed.ProcessPACInfoBuffersWithCredentialKey(reply.Key, replyKey, logger); err != nil {
		return fmt.Errorf("process PKINIT credential PAC: %w", err)
	}
	if err := parsed.Verify(reply.Key, pac.VerifyOptions{
		ExpectedClientName: cl.Credentials.CName().PrincipalNameString(),
		ExpectedAuthTime:   &response.Ticket.DecryptedEncPart.AuthTime,
	}); err != nil {
		return fmt.Errorf("verify PKINIT credential PAC: %w", err)
	}
	if parsed.CredentialsInfo == nil {
		return errors.New("PKINIT credential PAC omitted PAC_CREDENTIAL_INFO")
	}
	credentials := clonePKINITCredentialData(parsed.CredentialsInfo.PACCredentialData)
	cl.pkinitMux.Lock()
	cl.pkinitCreds = &credentials
	cl.pkinitCredErr = nil
	cl.pkinitMux.Unlock()
	return nil
}

func (cl *Client) newASReq() (messages.ASReq, error) {
	return cl.newASReqWithOptions(messages.ASReqOptions{})
}

func (cl *Client) newASReqWithOptions(options messages.ASReqOptions) (messages.ASReq, error) {
	req, err := messages.NewASReqForTGTWithOptions(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName(), options)
	if err != nil || !cl.Credentials.HasKeytab() {
		return req, err
	}
	available := cl.Credentials.Keytab().ETypesForPrincipal(keytab.Principal{
		Realm:      cl.Credentials.Domain(),
		Components: cl.Credentials.CName().NameString,
		NameType:   cl.Credentials.CName().NameType,
	})
	req.ReqBody.EType = intersectETypes(cl.Config.LibDefaults.DefaultTktEnctypeIDs, available)
	if len(req.ReqBody.EType) == 0 {
		return req, errors.New("no supported encryption types (config file error?)")
	}
	return req, nil
}

func intersectETypes(preferred, available []int32) []int32 {
	availableSet := make(map[int32]struct{}, len(available))
	for _, etypeID := range available {
		availableSet[etypeID] = struct{}{}
	}
	result := make([]int32, 0, len(preferred))
	for _, etypeID := range preferred {
		if _, ok := availableSet[etypeID]; ok {
			result = append(result, etypeID)
		}
	}
	return result
}

// AffirmLogin will only perform an AS exchange with the KDC if the client does not already have a TGT.
func (cl *Client) AffirmLogin() error {
	_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
	if err != nil || time.Now().UTC().After(endTime) {
		err := cl.Login()
		if err != nil {
			return fmt.Errorf("could not get valid TGT for client's realm: %v", err)
		}
	}
	return nil
}

// realmLogin obtains or renews a TGT and establishes a session for the realm specified.
func (cl *Client) realmLogin(realm string) error {
	if types.RealmEqual(realm, cl.Credentials.Domain()) {
		return cl.Login()
	}
	_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
	if err != nil || time.Now().UTC().After(endTime) {
		err := cl.Login()
		if err != nil {
			return fmt.Errorf("could not get valid TGT for client's realm: %v", err)
		}
	}
	tgt, skey, err := cl.sessionTGT(cl.Credentials.Domain())
	if err != nil {
		return err
	}

	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	_, tgsRep, err := cl.TGSREQGenerateAndExchange(spn, cl.Credentials.Domain(), tgt, skey, false)
	if err != nil {
		return err
	}
	cl.addSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)

	return nil
}

// Destroy stops the auto-renewal of all sessions and removes the sessions and cache entries from the client.
func (cl *Client) Destroy() {
	creds := credentials.New("", "")
	cl.fastArmorMux.Lock()
	if cl.fastArmorCl != nil {
		cl.fastArmorCl.Destroy()
		cl.fastArmorCl = nil
	}
	cl.fastArmorMux.Unlock()
	cl.sessions.destroy()
	cl.cache.clear()
	cl.s4uCache.clear()
	cl.pkinitMux.Lock()
	for realm, key := range cl.pkinitKeys {
		for index := range key.KeyValue {
			key.KeyValue[index] = 0
		}
		delete(cl.pkinitKeys, realm)
	}
	if cl.pkinitCreds != nil {
		for index := range cl.pkinitCreds.Credentials {
			for byteIndex := range cl.pkinitCreds.Credentials[index].Credentials {
				cl.pkinitCreds.Credentials[index].Credentials[byteIndex] = 0
			}
		}
	}
	cl.pkinitCreds = nil
	cl.pkinitCredErr = nil
	cl.pkinitMux.Unlock()
	cl.Credentials = creds
	cl.Log("client destroyed")
}

// Diagnostics runs a set of checks that the client is properly configured and writes details to the io.Writer provided.
func (cl *Client) Diagnostics(w io.Writer) error {
	cl.Print(w)
	var errs []string
	if cl.Credentials.HasKeytab() {
		var loginRealmEncTypes []int32
		for _, e := range cl.Credentials.Keytab().Entries {
			if types.RealmEqual(e.Principal.Realm, cl.Credentials.Realm()) {
				loginRealmEncTypes = append(loginRealmEncTypes, e.Key.KeyType)
			}
		}
		for _, et := range cl.Config.LibDefaults.DefaultTktEnctypeIDs {
			var etInKt bool
			for _, val := range loginRealmEncTypes {
				if val == et {
					etInKt = true
					break
				}
			}
			if !etInKt {
				errs = append(errs, fmt.Sprintf("default_tkt_enctypes specifies %d but this enctype is not available in the client's keytab", et))
			}
		}
		for _, et := range cl.Config.LibDefaults.PreferredPreauthTypes {
			var etInKt bool
			for _, val := range loginRealmEncTypes {
				if int(val) == et {
					etInKt = true
					break
				}
			}
			if !etInKt {
				errs = append(errs, fmt.Sprintf("preferred_preauth_types specifies %d but this enctype is not available in the client's keytab", et))
			}
		}
	}
	udpCnt, udpKDC, err := cl.Config.GetKDCs(cl.Credentials.Realm(), false)
	if err != nil {
		errs = append(errs, fmt.Sprintf("error when resolving KDCs for UDP communication: %v", err))
	}
	if udpCnt < 1 {
		errs = append(errs, "no KDCs resolved for communication via UDP.")
	} else {
		b, _ := json.MarshalIndent(&udpKDC, "", "  ")
		fmt.Fprintf(w, "UDP KDCs: %s\n", string(b))
	}
	tcpCnt, tcpKDC, err := cl.Config.GetKDCs(cl.Credentials.Realm(), false)
	if err != nil {
		errs = append(errs, fmt.Sprintf("error when resolving KDCs for TCP communication: %v", err))
	}
	if tcpCnt < 1 {
		errs = append(errs, "no KDCs resolved for communication via TCP.")
	} else {
		b, _ := json.MarshalIndent(&tcpKDC, "", "  ")
		fmt.Fprintf(w, "TCP KDCs: %s\n", string(b))
	}

	if len(errs) < 1 {
		return nil
	}
	err = errors.New(strings.Join(errs, "\n"))
	return err
}

// Print writes the details of the client to the io.Writer provided.
func (cl *Client) Print(w io.Writer) {
	c, _ := cl.Credentials.JSON()
	fmt.Fprintf(w, "Credentials:\n%s\n", c)

	s, _ := cl.sessions.JSON()
	fmt.Fprintf(w, "TGT Sessions:\n%s\n", s)

	c, _ = cl.cache.JSON()
	fmt.Fprintf(w, "Service ticket cache:\n%s\n", c)

	s, _ = cl.settings.JSON()
	fmt.Fprintf(w, "Settings:\n%s\n", s)

	j, _ := cl.Config.JSON()
	fmt.Fprintf(w, "Krb5 config:\n%s\n", j)

	k, _ := cl.Credentials.Keytab().JSON()
	fmt.Fprintf(w, "Keytab:\n%s\n", k)
}
