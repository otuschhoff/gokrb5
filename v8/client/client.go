// Package client provides a client library and methods for Kerberos 5 authentication.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
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
	clientSettings := NewSettings(settings...)
	return newClient(creds.WithPassword(password), krb5conf, clientSettings)
}

// NewWithKeytab creates a new client from a keytab credential.
func NewWithKeytab(
	username, realm string, kt *keytab.Keytab, krb5conf *config.Config, settings ...func(*Settings),
) *Client {
	if realm == "" && krb5conf != nil {
		realm = krb5conf.LibDefaults.DefaultRealm
	}
	creds := credentials.New(username, realm)
	clientSettings := NewSettings(settings...)
	return newClient(creds.WithKeytab(kt), krb5conf, clientSettings)
}

// NewFromPrincipalString creates a client from an MIT-style principal string.
// If the principal omits its realm, the configured default realm is used.
func NewFromPrincipalString(princ string, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	parsed, err := keytab.ParsePrincipal(princ)
	if err != nil {
		return nil, fmt.Errorf("invalid client principal: %w", err)
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
func NewFromPrincipalName(
	princ types.PrincipalName, realm string, krb5conf *config.Config, settings ...func(*Settings),
) *Client {
	if realm == "" && krb5conf != nil {
		realm = krb5conf.LibDefaults.DefaultRealm
	}
	creds := credentials.NewFromPrincipalName(princ, realm)
	return newClient(creds, krb5conf, NewSettings(settings...))
}

// NewFromCCache create a client from a populated client cache.
//
// WARNING: A client created from CCache does not automatically renew TGTs.
// Authentication will fail after the TGT expires.
func NewFromCCache(c *credentials.CCache, krb5conf *config.Config, settings ...func(*Settings)) (*Client, error) {
	if c == nil {
		return nil, errors.New("credential cache is nil")
	}
	clientSettings := NewSettings(settings...)
	cl := newClient(c.GetClientCredentials(), krb5conf, clientSettings)
	return cl, cl.importCCache(c)
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

func newClient(creds *credentials.Credentials, krb5conf *config.Config, settings *Settings) *Client {
	return &Client{
		Credentials:   creds,
		Config:        krb5conf,
		settings:      settings,
		sessions:      &sessions{Entries: make(map[string]*session), mux: sync.RWMutex{}},
		cache:         NewCache(),
		s4uCache:      NewCache(),
		loginMux:      sync.Mutex{},
		kdcTimeOffset: settings.kdcTimeOffset,
		kdcTimeMux:    sync.RWMutex{},
		fastArmorMux:  sync.Mutex{},
		fastArmorCl:   nil,
		pkinitMux:     sync.Mutex{},
		pkinitKeys:    nil,
		pkinitCreds:   nil,
		pkinitCredErr: nil,
		sendToKDCFunc: nil,
	}
}

const tgtPrincipalComponents = 2

// findTGTCredentialFold finds the krbtgt credential for realm, comparing the
// realm case-insensitively rather than requiring an exact string match.
func findTGTCredentialFold(entries []*credentials.Credential, realm string) (*credentials.Credential, bool) {
	for _, cred := range entries {
		name := cred.Server.PrincipalName.NameString
		if len(name) == tgtPrincipalComponents && name[0] == tgtServiceName && types.RealmEqual(name[1], realm) {
			return cred, true
		}
	}
	return nil, false
}

// KDCTimeOffset returns the time offset learned from the KDC.
func (cl *Client) KDCTimeOffset() time.Duration {
	if cl == nil {
		return 0
	}
	cl.kdcTimeMux.RLock()
	defer cl.kdcTimeMux.RUnlock()
	return cl.kdcTimeOffset
}

// Key returns the client's encryption key for the specified encryption type and kvno.
// A kvno of zero selects the latest key.
// The key comes from the keytab or is generated from the client's password.
// If the client has both a keytab and a password defined the keytab is favoured as the source for the key
// If the KDC returns KDC_ERR_PREAUTH_REQUIRED, pass it to derive the pre-authentication
// key from the client's password. Otherwise, pass nil.
func (cl *Client) Key(etype etype.EType, kvno int, krberr *messages.KRBError) (types.EncryptionKey, int, error) {
	if cl.Credentials.HasKeytab() && etype != nil {
		key, keyVersion, err := cl.Credentials.Keytab().GetEncryptionKey(
			cl.Credentials.CName(),
			cl.Credentials.Domain(),
			kvno,
			etype.GetETypeID(),
		)
		if err != nil {
			return key, keyVersion, fmt.Errorf("lookup keytab key: %w", err)
		}
		return key, keyVersion, nil
	}
	if !cl.Credentials.HasPassword() {
		return types.EncryptionKey{}, 0, errors.New("credential has neither keytab or password to generate key")
	}
	cname, realm := cl.Credentials.CName(), cl.Credentials.Domain()
	var paData types.PADataSequence
	if krberr != nil && (krberr.ErrorCode == errorcode.KDC_ERR_PREAUTH_REQUIRED ||
		krberr.ErrorCode == errorcode.KDC_ERR_PREAUTH_FAILED) {
		if err := paData.Unmarshal(krberr.EData); err != nil {
			return types.EncryptionKey{}, 0, fmt.Errorf(
				"could not get PAData from KRBError to generate key from password: %w", err,
			)
		}
		cname, realm = krberr.CName, krberr.CRealm
	}
	key, _, err := crypto.GetKeyFromPassword(cl.Credentials.Password(), cname, realm, etype.GetETypeID(), paData)
	if err != nil {
		return key, 0, fmt.Errorf("derive key from password: %w", err)
	}
	return key, 0, nil
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
	if !cl.hasLoginCredentials() {
		authTime, _, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
		if err != nil || authTime.IsZero() {
			return false, errors.New("client has neither a keytab nor a password set and no session")
		}
	}
	return cl.checkKDCConfiguration()
}

// Login the client with the KDC via an AS exchange.
func (cl *Client) Login() error {
	var options messages.ASReqOptions
	return cl.LoginWithOptions(options)
}

// LoginWithOptions logs the client in with per-request AS options.
func (cl *Client) LoginWithOptions(options messages.ASReqOptions) error {
	cl.loginMux.Lock()
	defer cl.loginMux.Unlock()

	if ok, err := cl.IsConfigured(); !ok {
		return err
	}
	if !cl.hasLoginCredentials() {
		return cl.loginFromExistingSession()
	}
	ASReq, err := cl.newASReqWithOptions(options)
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError, "error generating new AS_REQ")
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		return err
	}
	if name := ASRep.Ticket.SName.NameString; len(name) > 0 && strings.EqualFold(name[0], tgtServiceName) {
		cl.addLoginSession(ASRep.Ticket, ASRep.DecryptedEncPart)
		return nil
	}
	part := ASRep.DecryptedEncPart
	cl.cache.addEntryWithDetails(
		ASRep.Ticket, part.AuthTime, part.StartTime, part.EndTime, part.RenewTill,
		part.Key, part.Flags, part.CAddr, nil, false, nil,
	)
	return nil
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
		if lerr := cl.Login(); lerr != nil {
			return fmt.Errorf("could not get valid TGT for client's realm: %w", lerr)
		}
	}
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
	if err := cl.print(w); err != nil {
		return err
	}
	var errs []error
	if cl.Credentials.HasKeytab() {
		errs = cl.keytabDiagnosticErrors()
	}
	for _, transport := range []string{"UDP", "TCP"} {
		var writeErr error
		errs, writeErr = cl.writeKDCDiagnostics(w, transport, errs)
		if writeErr != nil {
			return errors.Join(append(errs, writeErr)...)
		}
	}
	return errors.Join(errs...)
}

func writeDiagnosticText(w io.Writer, text string) error {
	n, err := io.WriteString(w, text)
	if err == nil && n != len(text) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write client diagnostics: %w", err)
	}
	return nil
}

// Print writes the details of the client to the io.Writer provided.
// It logs encoding/output failures; use Diagnostics to receive these errors.
func (cl *Client) Print(w io.Writer) {
	if err := cl.print(w); err != nil {
		cl.Log("could not print client details: %v", err)
	}
}

func (cl *Client) importCCache(c *credentials.CCache) error {
	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{tgtServiceName, c.DefaultPrincipal.Realm},
	}
	entries := c.GetEntries()
	if len(entries) == 0 {
		return errors.New("credential cache contains no credentials")
	}
	tgtCredential, ok := c.GetEntry(spn)
	if !ok {
		// Realm casing in the ccache's default principal can differ from the
		// realm the KDC embedded in the TGT's service name (e.g. a custom
		// identity entered with different casing, or a cross-realm referral).
		// Fall back to a realm-insensitive match so a valid cached TGT is not
		// missed, which would otherwise leave no session registered and cause
		// a later Renew() to fail with "TGT session not found".
		tgtCredential, ok = findTGTCredentialFold(entries, c.DefaultPrincipal.Realm)
	}
	configCredential := entries[0]
	if ok {
		if err := cl.importCCacheTGT(tgtCredential, c.DefaultPrincipal.Realm); err != nil {
			return err
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
			return fmt.Errorf("invalid pa_type credential cache config value %q: %w", value, err)
		}
		cl.settings.preAuthType = int32(paType)
	}
	return cl.importCCacheServiceTickets(entries, tgtCredential)
}

func (cl *Client) importCCacheTGT(cred *credentials.Credential, realm string) error {
	var tgt messages.Ticket
	if err := tgt.Unmarshal(cred.Ticket); err != nil {
		return fmt.Errorf("TGT bytes in cache are not valid: %w", err)
	}
	if name := cred.Server.PrincipalName.NameString; len(name) == tgtPrincipalComponents {
		realm = name[1]
	}
	cl.sessions.Entries[strings.ToUpper(realm)] = &session{
		realm:                realm,
		authTime:             cred.AuthTime,
		startTime:            cred.StartTime,
		endTime:              cred.EndTime,
		renewTill:            cred.RenewTill,
		tgt:                  tgt,
		sessionKey:           cred.Key,
		ticketFlags:          cred.TicketFlags,
		addresses:            append([]types.HostAddress(nil), cred.Addresses...),
		authData:             append([]types.AuthorizationDataEntry(nil), cred.AuthData...),
		isSKey:               cred.IsSKey,
		secondTicket:         append([]byte(nil), cred.SecondTicket...),
		sessionKeyExpiration: time.Time{},
		supportedEncTypes:    0,
		cancel:               nil,
		mux:                  sync.RWMutex{},
	}
	return nil
}

func (cl *Client) importCCacheServiceTickets(
	entries []*credentials.Credential, tgtCredential *credentials.Credential,
) error {
	for _, cred := range entries {
		if cred == tgtCredential {
			continue
		}
		var tkt messages.Ticket
		if err := tkt.Unmarshal(cred.Ticket); err != nil {
			return fmt.Errorf("cache entry ticket bytes are not valid: %w", err)
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
	return nil
}

func (cl *Client) retrievePKINITCredentials(
	tgt messages.Ticket, reply messages.EncKDCRepPart, replyKey types.EncryptionKey,
) error {
	request, err := messages.NewUser2UserTGSReq(
		cl.Credentials.CName(), cl.Credentials.Domain(), cl.Config, tgt, reply.Key, cl.Credentials.CName(), false, tgt,
	)
	if err != nil {
		return fmt.Errorf("build PKINIT credential U2U request: %w", err)
	}
	_, response, err := cl.TGSExchange(request, cl.Credentials.Domain(), tgt, reply.Key, 0)
	if err != nil {
		return fmt.Errorf("request PKINIT credential U2U ticket: %w", err)
	}
	if ierr := response.Ticket.Decrypt(reply.Key); ierr != nil {
		return fmt.Errorf("decrypt PKINIT credential U2U ticket: %w", ierr)
	}
	return cl.processPKINITCredentials(response.Ticket.DecryptedEncPart, reply.Key, replyKey)
}

func (cl *Client) processPKINITCredentials(part messages.EncTicketPart, key, replyKey types.EncryptionKey) error {
	entries, err := part.AuthorizationData.EntriesOfType(adtype.ADWin2KPAC)
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
	if err := parsed.ProcessPACInfoBuffersWithCredentialKey(key, replyKey, logger); err != nil {
		return fmt.Errorf("process PKINIT credential PAC: %w", err)
	}
	var options pac.VerifyOptions
	options.ExpectedClientName = cl.Credentials.CName().PrincipalNameString()
	options.ExpectedAuthTime = &part.AuthTime
	if err := parsed.Verify(key, options); err != nil {
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
	var options messages.ASReqOptions
	return cl.newASReqWithOptions(options)
}

func (cl *Client) newASReqWithOptions(options messages.ASReqOptions) (messages.ASReq, error) {
	req, err := messages.NewASReqForTGTWithOptions(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName(), options)
	if err != nil {
		return req, fmt.Errorf("build initial AS request: %w", err)
	}
	if !cl.Credentials.HasKeytab() {
		return req, nil
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

// realmLogin obtains or renews a TGT and establishes a session for the realm specified.
func (cl *Client) realmLogin(realm string) error {
	if types.RealmEqual(realm, cl.Credentials.Domain()) {
		return cl.Login()
	}
	_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
	if err != nil || time.Now().UTC().After(endTime) {
		if lerr := cl.Login(); lerr != nil {
			return fmt.Errorf("could not get valid TGT for client's realm: %w", lerr)
		}
	}
	tgt, skey, err := cl.sessionTGT(cl.Credentials.Domain())
	if err != nil {
		return err
	}

	spn := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{tgtServiceName, realm},
	}

	_, tgsRep, err := cl.TGSREQGenerateAndExchange(spn, cl.Credentials.Domain(), tgt, skey, false)
	if err != nil {
		return err
	}
	cl.addSession(tgsRep.Ticket, tgsRep.DecryptedEncPart)

	return nil
}

func (cl *Client) setKDCTimeOffset(offset time.Duration) {
	if cl == nil {
		return
	}
	cl.kdcTimeMux.Lock()
	cl.kdcTimeOffset = offset
	cl.kdcTimeMux.Unlock()
}

func (cl *Client) sendKDCRequest(request []byte, realm string) ([]byte, error) {
	if cl.sendToKDCFunc != nil {
		return cl.sendToKDCFunc(request, realm)
	}
	return cl.sendToKDC(request, realm)
}

func (cl *Client) hasLoginCredentials() bool {
	if cl.Credentials.HasPassword() || cl.Credentials.HasKeytab() {
		return true
	}
	return cl.settings.pkinitOptions != nil && cl.settings.pkinitOptions.Identity != nil
}

func (cl *Client) checkKDCConfiguration() (bool, error) {
	if cl.Config.LibDefaults.DNSLookupKDC {
		return true, nil
	}
	for _, realm := range cl.Config.Realms {
		if !types.RealmEqual(realm.Realm, cl.Credentials.Domain()) {
			continue
		}
		if len(realm.KDC) == 0 {
			return false, errors.New("client krb5 config does not have any defined KDCs for the default realm")
		}
		return true, nil
	}
	return true, nil
}

func (cl *Client) loginFromExistingSession() error {
	_, endTime, _, _, err := cl.sessionTimes(cl.Credentials.Domain())
	if err != nil {
		return krberror.Errorf(err, krberror.KRBMsgError,
			"no user credentials available and error getting any existing session")
	}
	if time.Now().UTC().After(endTime) {
		//nolint:wrapcheck // This is a new classified error; there is no underlying error to wrap.
		return krberror.New(krberror.KRBMsgError,
			"cannot login, no user credentials available and no valid existing session")
	}
	return nil
}

func (cl *Client) addLoginSession(ticket messages.Ticket, part messages.EncKDCRepPart) {
	cl.addSession(ticket, part)
	replyKey, ok := cl.takePKINITReplyKey(cl.Credentials.Domain())
	if !ok {
		return
	}
	cl.pkinitMux.Lock()
	cl.pkinitCreds = nil
	cl.pkinitCredErr = nil
	cl.pkinitMux.Unlock()
	if err := cl.retrievePKINITCredentials(ticket, part, replyKey); err != nil {
		cl.pkinitMux.Lock()
		cl.pkinitCredErr = err
		cl.pkinitMux.Unlock()
		cl.Log("could not retrieve PKINIT PAC credentials: %v", err)
	}
}

func (cl *Client) keytabDiagnosticErrors() []error {
	var errs []error
	var loginRealmEncTypes []int32
	for _, e := range cl.Credentials.Keytab().Entries {
		if types.RealmEqual(e.Principal.Realm, cl.Credentials.Realm()) {
			loginRealmEncTypes = append(loginRealmEncTypes, e.Key.KeyType)
		}
	}
	for _, et := range cl.Config.LibDefaults.DefaultTktEnctypeIDs {
		if !slices.Contains(loginRealmEncTypes, et) {
			errs = append(errs, fmt.Errorf(
				"default_tkt_enctypes specifies %d but this enctype is not available in the client's keytab", et))
		}
	}
	for _, et := range cl.Config.LibDefaults.PreferredPreauthTypes {
		if !slices.ContainsFunc(loginRealmEncTypes, func(val int32) bool { return int(val) == et }) {
			errs = append(errs, fmt.Errorf(
				"preferred_preauth_types specifies %d but this enctype is not available in the client's keytab", et))
		}
	}
	return errs
}

func (cl *Client) writeKDCDiagnostics(w io.Writer, transport string, errs []error) ([]error, error) {
	// Preserve the diagnostic's existing lookup mode for both report sections.
	count, kdcs, err := cl.Config.GetKDCs(cl.Credentials.Realm(), false)
	if err != nil {
		errs = append(errs, fmt.Errorf("error when resolving KDCs for %s communication: %w", transport, err))
	}
	if count < 1 {
		return append(errs, fmt.Errorf("no KDCs resolved for communication via %s", transport)), nil
	}
	b, err := json.MarshalIndent(&kdcs, "", "  ")
	if err != nil {
		return errs, fmt.Errorf("encode %s KDC diagnostics: %w", transport, err)
	}
	if err := writeDiagnosticText(w, fmt.Sprintf("%s KDCs: %s\n", transport, b)); err != nil {
		return errs, fmt.Errorf("write %s KDC diagnostics: %w", transport, err)
	}
	return errs, nil
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

func (cl *Client) print(w io.Writer) error {
	for _, section := range []struct {
		title  string
		encode func() (string, error)
	}{
		{title: "Credentials", encode: cl.Credentials.JSON},
		{title: "TGT Sessions", encode: cl.sessions.JSON},
		{title: "Service ticket cache", encode: cl.cache.JSON},
		{title: "Settings", encode: cl.settings.JSON},
		{title: "Krb5 config", encode: cl.Config.JSON},
		{title: "Keytab", encode: cl.Credentials.Keytab().JSON},
	} {
		text, err := section.encode()
		if err != nil {
			return fmt.Errorf("encode %s diagnostics: %w", section.title, err)
		}
		if err := writeDiagnosticText(w, fmt.Sprintf("%s:\n%s\n", section.title, text)); err != nil {
			return err
		}
	}
	return nil
}
