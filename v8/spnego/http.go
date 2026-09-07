package spnego

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/goidentity/v6"
	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/service"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// Client side functionality //

// Client will negotiate authentication with a server using SPNEGO.
type Client struct {
	*http.Client
	krb5Client *client.Client
	spn        string
	reqs       []*http.Request
	options    KRB5TokenAPREQOptions
	contexts   sync.Map
	contextMu  sync.RWMutex
	context    gssapi.Context
}

type redirectErr struct {
	reqTarget *http.Request
}

func (e redirectErr) Error() string {
	return fmt.Sprintf("redirect to %v", e.reqTarget.URL)
}

type teeReadCloser struct {
	io.Reader
	io.Closer
}

// ContextMechanismFactory creates a fresh mechanism for one HTTP
// authentication exchange.
type ContextMechanismFactory func() gssapi.ContextMechanism

// NegotiatingClient performs multi-round SPNEGO authentication using generic
// context mechanisms such as NEGOEX/PKU2U.
type NegotiatingClient struct {
	*http.Client
	target  string
	factory ContextMechanismFactory
	mu      sync.RWMutex
	context gssapi.Context
}

// NewNegotiatingClient creates an HTTP client for a generic SPNEGO mechanism.
func NewNegotiatingClient(httpClient *http.Client, target string, factory ContextMechanismFactory) *NegotiatingClient {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &NegotiatingClient{Client: httpClient, target: target, factory: factory}
}

// Context returns the most recently established security context.
func (client *NegotiatingClient) Context() gssapi.Context {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.context
}

// Do performs an HTTP request and follows the Negotiate challenge exchange.
func (client *NegotiatingClient) Do(request *http.Request) (*http.Response, error) {
	if client.factory == nil {
		return nil, errors.New("SPNEGO mechanism factory is required")
	}
	mechanism := client.factory()
	if mechanism == nil {
		return nil, errors.New("SPNEGO mechanism factory returned nil")
	}
	negotiator := NewNegotiator(mechanism)
	var establishedContext gssapi.Context
	var done bool
	var authorization string
	var exchangeCookie *http.Cookie
	for attempt := 0; attempt < 10; attempt++ {
		current, err := cloneNegotiationRequest(request, attempt)
		if err != nil {
			return nil, err
		}
		if authorization != "" {
			current.Header.Set(HTTPHeaderAuthRequest, authorization)
		}
		if exchangeCookie != nil {
			current.AddCookie(exchangeCookie)
		}
		response, err := client.Client.Do(current)
		if err != nil {
			return response, err
		}
		for _, cookie := range response.Cookies() {
			if cookie.Name == contextHTTPExchangeCookie && cookie.MaxAge >= 0 {
				exchangeCookie = cookie
				break
			}
		}
		challenge, challengePresent, err := decodeNegotiateHeader(response.Header.Get(HTTPHeaderAuthResponse))
		if err != nil {
			response.Body.Close()
			return nil, err
		}
		if response.StatusCode != http.StatusUnauthorized {
			if len(challenge) > 0 {
				output, context, complete, stepErr := negotiator.InitSecContext(client.target, challenge)
				if stepErr != nil {
					response.Body.Close()
					return nil, stepErr
				}
				if len(output) != 0 || !complete {
					response.Body.Close()
					return nil, errors.New("HTTP server sent an incomplete final SPNEGO token")
				}
				establishedContext, done = context, complete
			}
			if authorization != "" && !done {
				response.Body.Close()
				return nil, errors.New("HTTP server completed without mutual SPNEGO authentication")
			}
			if done {
				client.mu.Lock()
				client.context = establishedContext
				client.mu.Unlock()
			}
			return response, nil
		}
		if !challengePresent {
			response.Body.Close()
			return nil, errors.New("HTTP 401 response does not advertise Negotiate")
		}
		output, context, complete, err := negotiator.InitSecContext(client.target, challenge)
		if err != nil {
			response.Body.Close()
			return nil, err
		}
		if context != nil {
			establishedContext = context
		}
		done = complete
		if len(output) == 0 {
			response.Body.Close()
			return nil, errors.New("SPNEGO mechanism produced no HTTP continuation token")
		}
		if err := discardAndClose(response.Body); err != nil {
			return nil, fmt.Errorf("discard HTTP 401 response: %w", err)
		}
		authorization = HTTPHeaderAuthResponseValueKey + " " + base64.StdEncoding.EncodeToString(output)
	}
	return nil, errors.New("HTTP SPNEGO authentication exceeded 10 round trips")
}

func cloneNegotiationRequest(request *http.Request, attempt int) (*http.Request, error) {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	if request.Body == nil {
		return clone, nil
	}
	if attempt == 0 {
		clone.Body = request.Body
		return clone, nil
	}
	if request.GetBody == nil {
		return nil, errors.New("HTTP request body cannot be replayed during SPNEGO authentication")
	}
	body, err := request.GetBody()
	if err != nil {
		return nil, err
	}
	clone.Body = body
	return clone, nil
}

func decodeNegotiateHeader(value string) ([]byte, bool, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 || !strings.EqualFold(fields[0], HTTPHeaderAuthResponseValueKey) {
		return nil, false, nil
	}
	if len(fields) == 1 {
		return nil, true, nil
	}
	if len(fields) != 2 {
		return nil, true, errors.New("invalid HTTP Negotiate challenge")
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, true, fmt.Errorf("decode HTTP Negotiate challenge: %w", err)
	}
	return decoded, true, nil
}

// NewClient returns a SPNEGO enabled HTTP client.
// Be careful when passing in the *http.Client if it is beginning reused in multiple calls to this function.
// Ensure reuse of the provided *http.Client is for the same user as a session cookie may have been added to
// http.Client's cookie jar.
// Incorrect reuse of the provided *http.Client could lead to access to the wrong user's session.
func NewClient(krb5Cl *client.Client, httpCl *http.Client, spn string) *Client {
	return NewClientWithOptions(krb5Cl, httpCl, spn, KRB5TokenAPREQOptions{
		GSSAPIFlags: []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf},
	})
}

// NewClientWithOptions returns an SPNEGO HTTP client with explicit GSS options.
func NewClientWithOptions(krb5Cl *client.Client, httpCl *http.Client, spn string, options KRB5TokenAPREQOptions) *Client {
	if httpCl == nil {
		httpCl = &http.Client{}
	}
	// Add a cookie jar if there isn't one
	if httpCl.Jar == nil {
		httpCl.Jar, _ = cookiejar.New(nil)
	}
	// Add a CheckRedirect function that will execute any functional already defined and then error with a redirectErr
	f := httpCl.CheckRedirect
	httpCl.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if f != nil {
			err := f(req, via)
			if err != nil {
				return err
			}
		}
		return redirectErr{reqTarget: req}
	}
	return &Client{
		Client:     httpCl,
		krb5Client: krb5Cl,
		spn:        spn,
		options:    options,
	}
}

// Context returns the most recently established mutual Kerberos security context.
func (c *Client) Context() gssapi.Context {
	c.contextMu.RLock()
	defer c.contextMu.RUnlock()
	return c.context
}

func (c *Client) setContext(context gssapi.Context) {
	c.contextMu.Lock()
	c.context = context
	c.contextMu.Unlock()
}

// Do is the SPNEGO enabled HTTP client's equivalent of the http.Client's Do method.
func (c *Client) Do(req *http.Request) (resp *http.Response, err error) {
	var body bytes.Buffer
	if req.Body != nil {
		// Use a tee reader to capture any body sent in case we have to replay it again
		teeR := io.TeeReader(req.Body, &body)
		teeRC := teeReadCloser{teeR, req.Body}
		req.Body = teeRC
	}
	resp, err = c.Client.Do(req)
	if err != nil {
		if ue, ok := err.(*url.Error); ok {
			if e, ok := ue.Err.(redirectErr); ok {
				if verifyErr := c.verifyMutualResponse(req, resp); verifyErr != nil {
					return resp, verifyErr
				}
				// Picked up a redirect
				e.reqTarget.Header.Del(HTTPHeaderAuthRequest)
				c.reqs = append(c.reqs, e.reqTarget)
				if len(c.reqs) >= 10 {
					return resp, errors.New("stopped after 10 redirects")
				}
				if req.Body != nil {
					// Refresh the body reader so the body can be sent again
					e.reqTarget.Body = io.NopCloser(&body)
				}
				return c.Do(e.reqTarget)
			}
		}
		return resp, err
	}
	if respUnauthorizedNegotiate(resp) {
		c.setContext(nil)
		spnegoContext, err := setSPNEGOHeaderWithOptions(c.krb5Client, req, c.spn, c.options)
		if err != nil {
			return resp, err
		}
		c.contexts.Store(req, spnegoContext)
		defer c.contexts.Delete(req)
		if req.Body != nil {
			// Refresh the body reader so the body can be sent again
			req.Body = io.NopCloser(&body)
		}
		if err := discardAndClose(resp.Body); err != nil {
			return resp, fmt.Errorf("discard HTTP 401 response: %w", err)
		}
		return c.Do(req)
	}
	if err := c.verifyMutualResponse(req, resp); err != nil {
		return resp, err
	}
	return resp, err
}

func discardAndClose(body io.ReadCloser) error {
	_, readErr := io.Copy(io.Discard, body)
	closeErr := body.Close()
	if readErr != nil {
		if closeErr != nil {
			return fmt.Errorf("read response body: %w (close also failed: %v)", readErr, closeErr)
		}
		return fmt.Errorf("read response body: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close response body: %w", closeErr)
	}
	return nil
}

func (c *Client) verifyMutualResponse(req *http.Request, resp *http.Response) error {
	pending, ok := c.contexts.LoadAndDelete(req)
	if !ok || !contextFlagSet(c.options.GSSAPIFlags, gssapi.ContextFlagMutual) {
		return nil
	}
	responseToken, err := responseSPNEGOToken(resp)
	if err != nil {
		return err
	}
	if responseToken == nil {
		return errors.New("server did not return a mutual-authentication token")
	}
	spnegoContext := pending.(*SPNEGO)
	authenticated, _, status := spnegoContext.ContinueSecContext(responseToken)
	if !authenticated || status.Code != gssapi.StatusComplete {
		return fmt.Errorf("server mutual authentication failed: %v", status)
	}
	securityContext := spnegoContext.SecurityContext()
	if securityContext == nil {
		return errors.New("server mutual authentication completed without a security context")
	}
	c.setContext(securityContext)
	return nil
}

// Get is the SPNEGO enabled HTTP client's equivalent of the http.Client's Get method.
func (c *Client) Get(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post is the SPNEGO enabled HTTP client's equivalent of the http.Client's Post method.
func (c *Client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// PostForm is the SPNEGO enabled HTTP client's equivalent of the http.Client's PostForm method.
func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}

// Head is the SPNEGO enabled HTTP client's equivalent of the http.Client's Head method.
func (c *Client) Head(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func respUnauthorizedNegotiate(resp *http.Response) bool {
	if resp.StatusCode == http.StatusUnauthorized {
		if resp.Header.Get(HTTPHeaderAuthResponse) == HTTPHeaderAuthResponseValueKey {
			return true
		}
	}
	return false
}

func setRequestSPN(r *http.Request) (types.PrincipalName, error) {
	h := strings.TrimSuffix(r.URL.Host, ".")
	// This if statement checks if the host includes a port number
	if strings.LastIndex(r.URL.Host, ":") > strings.LastIndex(r.URL.Host, "]") {
		// There is a port number in the URL
		h, p, err := net.SplitHostPort(h)
		if err != nil {
			return types.PrincipalName{}, err
		}
		name, err := net.LookupCNAME(h)
		if name != "" && err == nil {
			// Underlyng canonical name should be used for SPN
			h = strings.ToLower(name)
		}
		h = strings.TrimSuffix(h, ".")
		r.Host = fmt.Sprintf("%s:%s", h, p)
		return types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/"+h), nil
	}
	name, err := net.LookupCNAME(h)
	if name != "" && err == nil {
		// Underlyng canonical name should be used for SPN
		h = strings.ToLower(name)
	}
	h = strings.TrimSuffix(h, ".")
	r.Host = h
	return types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/"+h), nil
}

// SetSPNEGOHeader gets the service ticket and sets it as the SPNEGO authorization header on HTTP request object.
// To auto generate the SPN from the request object pass a null string "".
func SetSPNEGOHeader(cl *client.Client, r *http.Request, spn string) error {
	_, err := setSPNEGOHeaderWithOptions(cl, r, spn, KRB5TokenAPREQOptions{
		GSSAPIFlags: []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf},
	})
	return err
}

// SetSPNEGOHeaderWithOptions sets a SPNEGO Authorization header and returns
// the initiating context so callers can verify a mutual-authentication reply.
func SetSPNEGOHeaderWithOptions(cl *client.Client, r *http.Request, spn string, options KRB5TokenAPREQOptions) (*SPNEGO, error) {
	return setSPNEGOHeaderWithOptions(cl, r, spn, options)
}

func setSPNEGOHeaderWithOptions(cl *client.Client, r *http.Request, spn string, options KRB5TokenAPREQOptions) (*SPNEGO, error) {
	if contextFlagSet(options.GSSAPIFlags, gssapi.ContextFlagDCEStyle) {
		return nil, errors.New("DCE-style context exchange is not supported over HTTP")
	}
	if spn == "" {
		pn, err := setRequestSPN(r)
		if err != nil {
			return nil, err
		}
		spn = pn.PrincipalNameString()
	}
	cl.Log("using SPN %s", spn)
	s := SPNEGOClientWithOptions(cl, spn, options)
	err := s.AcquireCred()
	if err != nil {
		return nil, fmt.Errorf("could not acquire client credential: %v", err)
	}
	st, err := s.InitSecContext()
	if err != nil {
		return nil, fmt.Errorf("could not initialize context: %v", err)
	}
	nb, err := st.Marshal()
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "could not marshal SPNEGO")
	}
	hs := "Negotiate " + base64.StdEncoding.EncodeToString(nb)
	r.Header.Set(HTTPHeaderAuthRequest, hs)
	return s, nil
}

func responseSPNEGOToken(resp *http.Response) (*SPNEGOToken, error) {
	parts := strings.SplitN(resp.Header.Get(HTTPHeaderAuthResponse), " ", 2)
	if len(parts) != 2 || parts[0] != HTTPHeaderAuthResponseValueKey {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid SPNEGO response encoding: %v", err)
	}
	var token SPNEGOToken
	if err := token.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("invalid SPNEGO response token: %v", err)
	}
	return &token, nil
}

// Service side functionality //

const (
	// spnegoNegTokenRespKRBAcceptCompleted - The response on successful authentication always has this header. Capturing as const so we don't have marshaling and encoding overhead.
	spnegoNegTokenRespKRBAcceptCompleted = "Negotiate oRQwEqADCgEAoQsGCSqGSIb3EgECAg=="
	// spnegoNegTokenRespReject - The response on a failed authentication always has this rejection header. Capturing as const so we don't have marshaling and encoding overhead.
	spnegoNegTokenRespReject = "Negotiate oQcwBaADCgEC"
	// spnegoNegTokenRespIncompleteKRB5 - Response token specifying incomplete context and KRB5 as the supported mechtype.
	spnegoNegTokenRespIncompleteKRB5 = "Negotiate oRQwEqADCgEBoQsGCSqGSIb3EgECAg=="
	// sessionCredentials is the session value key holding the credentials jcmturner/goidentity/Identity object.
	sessionCredentials = "github.com/otuschhoff/gokrb5/v8/sessionCredentials"
	// ctxCredentials is the SPNEGO context key holding the credentials jcmturner/goidentity/Identity object.
	ctxCredentials = "github.com/otuschhoff/gokrb5/v8/ctxCredentials"
	// HTTPHeaderAuthRequest is the header that will hold authn/z information.
	HTTPHeaderAuthRequest = "Authorization"
	// HTTPHeaderAuthResponse is the header that will hold SPNEGO data from the server.
	HTTPHeaderAuthResponse = "WWW-Authenticate"
	// HTTPHeaderAuthResponseValueKey is the key in the auth header for SPNEGO.
	HTTPHeaderAuthResponseValueKey = "Negotiate"
	// UnauthorizedMsg is the message returned in the body when authentication fails.
	UnauthorizedMsg = "Unauthorised.\n"
)

// SPNEGOKRB5Authenticate is a Kerberos SPNEGO authentication HTTP handler wrapper.
func SPNEGOKRB5Authenticate(inner http.Handler, kt *keytab.Keytab, settings ...func(*service.Settings)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set up the SPNEGO GSS-API mechanism
		var spnego *SPNEGO
		h, err := types.GetHostAddress(r.RemoteAddr)
		if err == nil {
			// put in this order so that if the user provides a ClientAddress it will override the one here.
			o := append([]func(*service.Settings){service.ClientAddress(h)}, settings...)
			spnego = SPNEGOService(kt, o...)
		} else {
			spnego = SPNEGOService(kt, settings...)
			spnego.Log("%s - SPNEGO could not parse client address: %v", r.RemoteAddr, err)
		}

		// Check if there is a session manager and if there is an already established session for this client
		id, err := getSessionCredentials(spnego, r)
		if err == nil && id.Authenticated() {
			// There is an established session so bypass auth and serve
			spnego.Log("%s - SPNEGO request served under session %s", r.RemoteAddr, id.SessionID())
			inner.ServeHTTP(w, goidentity.AddToHTTPRequestContext(&id, r))
			return
		}

		st, err := getAuthorizationNegotiationHeaderAsSPNEGOToken(spnego, r, w)
		if st == nil || err != nil {
			// response to client and logging handled in function above so just return
			return
		}

		// Validate the context token
		authed, ctx, status := spnego.AcceptSecContext(st)
		if status.Code != gssapi.StatusComplete && status.Code != gssapi.StatusContinueNeeded {
			spnegoResponseReject(spnego, w, "%s - SPNEGO validation error: %v", r.RemoteAddr, status)
			return
		}
		if status.Code == gssapi.StatusContinueNeeded {
			spnegoNegotiateKRB5MechType(spnego, w, "%s - SPNEGO GSS-API continue needed", r.RemoteAddr)
			return
		}

		if authed {
			// Authentication successful; get user's credentials from the context
			id := ctx.Value(ctxCredentials).(*credentials.Credentials)
			// Create a new session if a session manager has been configured
			err = newSession(spnego, r, w, id)
			if err != nil {
				return
			}
			spnegoResponseAcceptCompleted(spnego, w, "%s %s@%s - SPNEGO authentication succeeded", r.RemoteAddr, id.UserName(), id.Domain())
			// Add the identity to the context and serve the inner/wrapped handler
			inner.ServeHTTP(w, goidentity.AddToHTTPRequestContext(id, r))
			return
		}
		// If we get to here we have not authenticationed so just reject
		spnegoResponseReject(spnego, w, "%s - SPNEGO Kerberos authentication failed", r.RemoteAddr)
	})
}

type contextHTTPExchange struct {
	mu         sync.Mutex
	negotiator *Negotiator
	expires    time.Time
}

const (
	contextHTTPExchangeCookie = "gokrb5_spnego_exchange"
	contextHTTPExchangeTTL    = 2 * time.Minute
)

// SPNEGOContextAuthenticate authenticates HTTP requests with a generic,
// multi-round SPNEGO mechanism. The factory must return a fresh mechanism.
func SPNEGOContextAuthenticate(inner http.Handler, factory ContextMechanismFactory) http.Handler {
	var exchanges sync.Map
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		input, present, err := decodeNegotiateHeader(request.Header.Get(HTTPHeaderAuthRequest))
		if err != nil || !present || len(input) == 0 {
			writer.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
			http.Error(writer, UnauthorizedMsg, http.StatusUnauthorized)
			return
		}
		if factory == nil {
			http.Error(writer, UnauthorizedMsg, http.StatusUnauthorized)
			return
		}
		now := time.Now()
		exchanges.Range(func(key, value interface{}) bool {
			if now.After(value.(*contextHTTPExchange).expires) {
				exchanges.Delete(key)
			}
			return true
		})
		exchangeID := ""
		if cookie, cookieErr := request.Cookie(contextHTTPExchangeCookie); cookieErr == nil {
			exchangeID = cookie.Value
		}
		value, ok := exchanges.Load(exchangeID)
		if !ok {
			mechanism := factory()
			if mechanism == nil {
				http.Error(writer, UnauthorizedMsg, http.StatusUnauthorized)
				return
			}
			var idBytes [16]byte
			if _, err := rand.Read(idBytes[:]); err != nil {
				http.Error(writer, UnauthorizedMsg, http.StatusUnauthorized)
				return
			}
			exchangeID = hex.EncodeToString(idBytes[:])
			value = &contextHTTPExchange{negotiator: NewNegotiator(mechanism), expires: now.Add(contextHTTPExchangeTTL)}
			exchanges.Store(exchangeID, value)
			http.SetCookie(writer, &http.Cookie{
				Name: contextHTTPExchangeCookie, Value: exchangeID, Path: "/", MaxAge: int(contextHTTPExchangeTTL.Seconds()),
				HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: request.TLS != nil,
			})
		}
		exchange := value.(*contextHTTPExchange)
		exchange.mu.Lock()
		output, context, done, stepErr := exchange.negotiator.AcceptSecContext(input)
		exchange.mu.Unlock()
		if stepErr != nil {
			exchanges.Delete(exchangeID)
			expireContextHTTPExchangeCookie(writer, request)
			writer.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
			http.Error(writer, UnauthorizedMsg, http.StatusUnauthorized)
			return
		}
		responseHeader := HTTPHeaderAuthResponseValueKey
		if len(output) > 0 {
			responseHeader += " " + base64.StdEncoding.EncodeToString(output)
		}
		writer.Header().Set(HTTPHeaderAuthResponse, responseHeader)
		if !done {
			http.Error(writer, UnauthorizedMsg, http.StatusUnauthorized)
			return
		}
		exchanges.Delete(exchangeID)
		expireContextHTTPExchangeCookie(writer, request)
		credentialContext, ok := context.(interface {
			Credentials() *credentials.Credentials
		})
		if !ok || credentialContext.Credentials() == nil {
			http.Error(writer, UnauthorizedMsg, http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(writer, goidentity.AddToHTTPRequestContext(credentialContext.Credentials(), request))
	})
}

func expireContextHTTPExchangeCookie(writer http.ResponseWriter, request *http.Request) {
	http.SetCookie(writer, &http.Cookie{
		Name: contextHTTPExchangeCookie, Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: request.TLS != nil,
	})
}

func getAuthorizationNegotiationHeaderAsSPNEGOToken(spnego *SPNEGO, r *http.Request, w http.ResponseWriter) (*SPNEGOToken, error) {
	s := strings.SplitN(r.Header.Get(HTTPHeaderAuthRequest), " ", 2)
	if len(s) != 2 || s[0] != HTTPHeaderAuthResponseValueKey {
		// No Authorization header set so return 401 with WWW-Authenticate Negotiate header
		w.Header().Set(HTTPHeaderAuthResponse, HTTPHeaderAuthResponseValueKey)
		http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
		return nil, errors.New("client did not provide a negotiation authorization header")
	}

	// Decode the header into an SPNEGO context token
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		err = fmt.Errorf("error in base64 decoding negotiation header: %v", err)
		spnegoNegotiateKRB5MechType(spnego, w, "%s - SPNEGO %v", r.RemoteAddr, err)
		return nil, err
	}
	var st SPNEGOToken
	err = st.Unmarshal(b)
	if err != nil {
		// Check if this is a raw KRB5 context token - issue #347.
		var k5t KRB5Token
		if k5t.Unmarshal(b) != nil {
			err = fmt.Errorf("error in unmarshaling SPNEGO token: %v", err)
			spnegoNegotiateKRB5MechType(spnego, w, "%s - SPNEGO %v", r.RemoteAddr, err)
			return nil, err
		}
		// Wrap it into an SPNEGO context token
		st.Init = true
		st.NegTokenInit = NegTokenInit{
			MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
			MechTokenBytes: b,
		}
	}
	return &st, nil
}

func getSessionCredentials(spnego *SPNEGO, r *http.Request) (credentials.Credentials, error) {
	var creds credentials.Credentials
	// Check if there is a session manager and if there is an already established session for this client
	if sm := spnego.serviceSettings.SessionManager(); sm != nil {
		cb, err := sm.Get(r, sessionCredentials)
		if err != nil || cb == nil || len(cb) < 1 {
			return creds, fmt.Errorf("%s - SPNEGO error getting session and credentials for request: %v", r.RemoteAddr, err)
		}
		err = creds.Unmarshal(cb)
		if err != nil {
			return creds, fmt.Errorf("%s - SPNEGO credentials malformed in session: %v", r.RemoteAddr, err)
		}
		return creds, nil
	}
	return creds, errors.New("no session manager configured")
}

func newSession(spnego *SPNEGO, r *http.Request, w http.ResponseWriter, id *credentials.Credentials) error {
	if sm := spnego.serviceSettings.SessionManager(); sm != nil {
		// create new session
		idb, err := id.Marshal()
		if err != nil {
			spnegoInternalServerError(spnego, w, "SPNEGO could not marshal credentials to add to the session: %v", err)
			return err
		}
		err = sm.New(w, r, sessionCredentials, idb)
		if err != nil {
			spnegoInternalServerError(spnego, w, "SPNEGO could not create new session: %v", err)
			return err
		}
		spnego.Log("%s %s@%s - SPNEGO new session (%s) created", r.RemoteAddr, id.UserName(), id.Domain(), id.SessionID())
	}
	return nil
}

// Log and respond to client for error conditions

func spnegoNegotiateKRB5MechType(s *SPNEGO, w http.ResponseWriter, format string, v ...interface{}) {
	s.Log(format, v...)
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespIncompleteKRB5)
	http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
}

func spnegoResponseReject(s *SPNEGO, w http.ResponseWriter, format string, v ...interface{}) {
	s.Log(format, v...)
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespReject)
	http.Error(w, UnauthorizedMsg, http.StatusUnauthorized)
}

func spnegoResponseAcceptCompleted(s *SPNEGO, w http.ResponseWriter, format string, v ...interface{}) {
	s.Log(format, v...)
	if token := s.ResponseToken(); token != nil {
		b, err := token.Marshal()
		if err != nil {
			spnegoInternalServerError(s, w, "SPNEGO could not marshal response token: %v", err)
			return
		}
		w.Header().Set(HTTPHeaderAuthResponse, "Negotiate "+base64.StdEncoding.EncodeToString(b))
		return
	}
	w.Header().Set(HTTPHeaderAuthResponse, spnegoNegTokenRespKRBAcceptCompleted)
}

func spnegoInternalServerError(s *SPNEGO, w http.ResponseWriter, format string, v ...interface{}) {
	s.Log(format, v...)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
