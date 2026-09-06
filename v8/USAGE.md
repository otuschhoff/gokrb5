## Version 8 Usage

### Command-line tools

Version 8 includes MIT-compatible command-line tools for acquiring, inspecting,
and destroying credentials:

```sh
go install github.com/otuschhoff/gokrb5/v8/cmd/gokinit
go install github.com/otuschhoff/gokrb5/v8/cmd/goklist
go install github.com/otuschhoff/gokrb5/v8/cmd/gokdestroy
```

`gokinit` honors `KRB5_CONFIG`, `KRB5CCNAME`, `KRB5_KTNAME`, and
`KRB5_CLIENT_KTNAME`. It supports password and keytab acquisition, ticket and
renewal lifetimes, forwardable/proxiable/address options, canonical and
enterprise principals, initial service tickets, and TGT renewal:

```sh
gokinit user@EXAMPLE.COM
gokinit -k -t /path/to/user.keytab user@EXAMPLE.COM
gokinit -l 2h -r 7d -f user@EXAMPLE.COM
gokinit -R -c FILE:/tmp/krb5cc_1000
```

Passwords are read without echo from the controlling terminal. Reading a
password from standard input requires the explicit `--password-stdin` option.
Credential cache commands currently support FILE caches. Validation with `-v`
is not implemented and returns `kinit: -v not supported`.

```sh
goklist -c FILE:/tmp/krb5cc_1000 -e
goklist -k -t -K -e /path/to/user.keytab
gokdestroy -c FILE:/tmp/krb5cc_1000
```

### Configuration
The gokrb5 libraries use the same krb5.conf configuration file format as MIT Kerberos, 
described [here](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).
Config instances can be created by loading from a file path or by passing a string, io.Reader or bufio.Scanner to the 
relevant method:
```go
import "github.com/otuschhoff/gokrb5/v8/config"
cfg, err := config.Load("/path/to/config/file")
cfg, err := config.NewFromString(krb5Str) //String must have appropriate newline separations
cfg, err := config.NewFromReader(reader)
cfg, err := config.NewFromScanner(scanner)
```
### Keytab files
Standard keytab files can be read from a file or from a slice of bytes:
```go
import 	"github.com/otuschhoff/gokrb5/v8/keytab"
ktFromFile, err := keytab.Load("/path/to/file.keytab")
ktFromBytes, err := keytab.Parse(b)

```

Keytabs can also be created, modified, and written atomically. `AddKey` accepts
raw key material, while `AddEntry` and `AddEntryWithSalt` derive keys from a
password. KVNO values use `uint32`, including values greater than 255.

```go
principal, err := keytab.ParsePrincipal("user@EXAMPLE.COM")
kt := keytab.New()
err = kt.AddKey(principal, 300, key, time.Now())
err = kt.WriteFile("FILE:/path/to/user.keytab")
```

`LoadDefault` and `LoadDefaultClient` honor `KRB5_KTNAME`,
`KRB5_CLIENT_KTNAME`, and their krb5.conf defaults. `AppendToFile` uses an
advisory file lock where supported; external writers that ignore advisory
locking must still be coordinated by the caller.

### Credential caches

MIT FILE credential caches can be created and exported for use by MIT tools:

```go
cache, err := cl.CCache()
err = cache.WriteFile("FILE:/tmp/krb5cc_custom")
```

`credentials.NewCCache`, `AddCredential`, `SetConfig`, and `SetKDCTimeOffset`
support constructing caches directly. `DefaultCCacheName` resolves
`KRB5CCNAME`, `default_ccache_name`, and the platform fallback. Only FILE
caches are currently supported for writing.

---

### Kerberos Client
**Create** a client instance with either a password or a keytab.
A configuration must also be passed. Additionally optional additional settings can be provided.
```go
import 	"github.com/otuschhoff/gokrb5/v8/client"
cl := client.NewWithPassword("username", "REALM.COM", "password", cfg)
cl := client.NewWithKeytab("username", "REALM.COM", kt, cfg)
```
Optional settings are provided using the functions defined in the ``client/settings.go`` source file.

**Login**:
```go
err := cl.Login()
```
Kerberos Ticket Granting Tickets (TGT) will be automatically renewed unless the client was created from a CCache.

A client can be **destroyed** with the following method:
```go
cl.Destroy()
```

#### FAST armoring and Active Directory claims

The client can armor AS exchanges with an existing TGT and session key:

```go
cl := client.NewWithPassword("username", "REALM.COM", "password", cfg,
	client.FASTArmor(armorTGT, armorSessionKey),
)
```

When the armor identity differs from the client identity, provide it explicitly:

```go
cl := client.NewWithPassword("username", "REALM.COM", "password", cfg,
	client.FASTArmorWithIdentity(armorTGT, armorSessionKey, armorPrincipal, armorRealm),
)
```

Alternatively, `client.FASTArmorFromKeytab(kt)` acquires the armor TGT. A
machine-account principal (a single component ending in `$`) is preferred when
the keytab contains one; this is the form used for Active Directory compound
identity and device claims. User keytabs are also accepted, but do not provide
a device identity.

With armor configured, FAST activates when the KDC advertises PA-FX-FAST or
the realm metadata advertises FAST support. `client.RequireFAST(true)` activates
it immediately and rejects unprotected errors or replies. AS exchanges use an
AP-REQ armor and PA-ENCRYPTED-CHALLENGE; TGS exchanges use the ticket's implicit
armor. Claims are requested through PA-PAC-OPTIONS when the KDC advertises
claims support, and validated user and device claims are available through
`credentials.ADCredentials`.

#### KDC proxy transport

HTTPS KDC proxy endpoints can be configured directly in `krb5.conf`. The same
endpoint may be used for ticket requests and password changes:

```ini
[realms]
 EXAMPLE.ORG = {
  kdc = https://proxy.example.org/KdcProxy
  kpasswd_server = https://proxy.example.org/KdcProxy
 }
```

The client sends MS-KKDCP `KDC-PROXY-MESSAGE` requests with the target realm
and validates the framed Kerberos response. By default it uses an HTTP client
with a five-second timeout and the system TLS trust store. Supply a custom
client when private roots, client certificates, or custom proxy behavior are
required:

```go
httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
cl := client.NewWithPassword("username", "EXAMPLE.ORG", "password", cfg,
	client.KKDCPClient(httpClient),
)
```

Only HTTPS proxy URLs are accepted. The optional DC locator hint is omitted,
allowing the proxy to use its default writable-DC discovery flags.

#### Authenticate to a Service

##### HTTP SPNEGO
Create the HTTP request object and then create an SPNEGO client and use this to process the request with methods that 
are the same as on a HTTP client.
If nil is passed as the HTTP client when creating the SPNEGO client the http.DefaultClient is used.
When creating the SPNEGO client pass the Service Principal Name (SPN) or auto generate the SPN from the request 
object by passing a null string "".
```go
r, _ := http.NewRequest("GET", "http://host.test.gokrb5/index.html", nil)
spnegoCl := spnego.NewClient(cl, nil, "")
resp, err := spnegoCl.Do(r)
```

The standard Kerberos OID is offered by default. To interoperate with peers that prefer Microsoft's legacy Kerberos
OID, provide an explicit preference order. This changes only the SPNEGO mechanism identifiers; it does not enable
legacy RC4 encryption.
```go
options := spnego.KRB5TokenAPREQOptions{
	GSSAPIFlags: []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf},
	MechTypes: []asn1.ObjectIdentifier{
		gssapi.OIDMSLegacyKRB5.OID(),
		gssapi.OIDKRB5.OID(),
	},
}
spnegoCl := spnego.NewClientWithOptions(cl, nil, "", options)
```

Low-level callers can marshal and parse NegTokenInit2 by setting or reading `NegTokenInit.NegHints`. The
`SetMechListMIC` and `VerifyMechListMIC` methods protect the DER-encoded mechanism list when managing negotiation
tokens directly.

##### Generic Kerberos Client
To authenticate to a service a client will need to request a service ticket for a Service Principal Name (SPN) and form 
into an AP_REQ message along with an authenticator encrypted with the session key that was delivered from the KDC along 
with the service ticket.

The steps below outline how to do this.
* Get the service ticket and session key for the service the client is authenticating to.
The following method will use the client's cache either returning a valid cached ticket, renewing a cached ticket with 
the KDC or requesting a new ticket from the KDC.
Therefore the GetServiceTicket method can be continually used for the most efficient interaction with the KDC.
```go
tkt, key, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
```

##### Service for User and Constrained Delegation

A service account can request a ticket to itself for an authenticated user with
S4U2self. The user ticket is cached separately from the service account's own
ticket under the user, realm, and SPN.

```go
user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
evidence, _, err := cl.GetServiceTicketForUser(
    user,
    "EXAMPLE.COM",
    "HTTP/service.example.com",
    client.S4UWithForwardable(true),
)
```

The KDC decides whether the returned evidence ticket is forwardable. Its
issued state is available from the S4U cache:

```go
info, ok := cl.GetCachedServiceTicketForUserInfo(
    user,
    "EXAMPLE.COM",
    "HTTP/service.example.com",
)
if ok && info.Forwardable {
    // The ticket can be offered for classic constrained delegation.
}
```

Use the evidence ticket for S4U2proxy. Add the resource-based option when the
target account authorizes the calling service through RBCD.

```go
ticket, key, err := cl.GetServiceTicketOnBehalfOf(
    evidence,
    "HTTP/target.example.com",
    client.S4UWithResourceBasedDelegation(),
)
```

Policy denials preserve the KDC error and extended NTSTATUS while exposing
stable classifications:

```go
if errors.Is(err, krberror.ErrProtocolTransitionNotPermitted) {
    // S4U2self was denied.
}
if errors.Is(err, krberror.ErrDelegationNotPermitted) {
    // S4U2proxy was denied.
}
```

`S4UWithCertificate` accepts a DER-encoded X.509 certificate for
PA-S4U-X509-USER. Cross-realm S4U referrals are followed automatically.

The steps after this will be specific to the application protocol but it will likely involve a client/server 
Authentication Protocol exchange (AP exchange).
This will involve these steps:

* Generate a new Authenticator and generate a sequence number and subkey:
```go
auth, _ := types.NewAuthenticator(cl.Credentials.Realm, cl.Credentials.CName)
etype, _ := crypto.GetEtype(key.KeyType)
auth.GenerateSeqNumberAndSubKey(key.KeyType, etype.GetKeyByteSize())
```
* Set the checksum on the authenticator
The checksum is an application specific value. Set as follows:
```go
auth.Cksum = types.Checksum{
		CksumType: checksumIDint,
		Checksum:  checksumBytesSlice,
	}
```
* Create the AP_REQ:
```go
APReq, err := messages.NewAPReq(tkt, key, auth)
```

Now send the AP_REQ to the service. How this is done will be specific to the application use case.

#### Changing a Client Password
This feature uses the Microsoft Kerberos Password Change protocol (RFC 3244). 
This is implemented in Microsoft Active Directory and in MIT krb5kdc as of version 1.7.
Typically the kpasswd server listens on port 464.

Below is example code for how to use this feature:
```go
cfg, err := config.Load("/path/to/config/file")
if err != nil {
	panic(err.Error())
}
kt, err := keytab.Load("/path/to/file.keytab")
if err != nil {
	panic(err.Error())
}
cl := client.NewWithKeytab("username", "REALM.COM", kt)
cl.WithConfig(cfg)

ok, err := cl.ChangePasswd("newpassword")
if err != nil {
	panic(err.Error())
}
if !ok {
	panic("failed to change password")
}
```

The client kerberos config (krb5.conf) will need to have either the kpassd_server or admin_server defined in the 
relevant [realms] section. For example:
```
REALM.COM = {
  kdc = 127.0.0.1:88
  kpasswd_server = 127.0.0.1:464
  default_domain = realm.com
 }
```
See https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html#realms for more information.

#### Client Diagnostics
In the event of issues the configuration of a client can be investigated with its ``Diagnostics`` method.
This will check that the required enctypes defined in the client's krb5 config are available in its keytab.
It will also check that KDCs can be resolved for the client's REALM.
The error returned will contain details of any failed checks.
The configuration details of the client will be written to the ``io.Writer`` provided.

---

### Kerberised Service

#### SPNEGO/Kerberos HTTP Service
A HTTP handler wrapper can be used to implement Kerberos SPNEGO authentication for web services.
To configure the wrapper the keytab for the SPN and a Logger are required:
```go
kt, err := keytab.Load("/path/to/file.keytab")
l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
```
Create a handler function of the application's handling method (apphandler in the example below):
```go
h := http.HandlerFunc(apphandler)
```
Configure the HTTP handler:
```go
http.Handler("/", spnego.SPNEGOKRB5Authenticate(h, &kt, service.Logger(l)))
```
The handler to be wrapped and the keytab are required arguments. 
Additional optional settings can be provided, such as the logger shown above.

Another example of optional settings may be that when using Active Directory where the SPN is mapped to a user account 
the keytab may contain an entry for this user account. In this case this should be specified as below with the 
``KeytabPrincipal``:
```go
http.Handler("/", spnego.SPNEGOKRB5Authenticate(h, &kt, service.Logger(l), service.KeytabPrincipal(pn)))
```

##### Session Management
For efficiency reasons it is not desirable to authenticate on every call to a web service. 
Therefore most authenticated web applications implement some form of session with the user.
Such sessions can be supported by passing a "session manager" into the ``SPNEGOKRB5Authenticate`` wrapper handler.
In order to not demand a specific session manager solution, the session manager must implement a simple interface:
```go
type SessionMgr interface {
	New(w http.ResponseWriter, r *http.Request, k string, v []byte) error
	Get(r *http.Request, k string) ([]byte, error)
}
```
- New - creates a new session for the request and adds a piece of data (key/value pair) to the session
- Get - extract from an existing session the value held within it under the key provided. 
This should return nil bytes or an error if there is no existing session.

The session manager (sm) that implements this interface should then be passed to the ``SPNEGOKRB5Authenticate`` wrapper 
handler as below:
```go
http.Handler("/", spnego.SPNEGOKRB5Authenticate(h, &kt, service.Logger(l), service.SessionManager(sm)))
```

The ``httpServer.go`` source file in the examples directory shows how this can be used with the popular gorilla web toolkit.

##### Validating Users and Accessing Users' Details
If authentication succeeds then the request's context will have a credentials objected added to it.
This object implements the ``github.com/jcmturner/goidentity/identity`` interface.
If Microsoft Active Directory is used as the KDC then additional ADCredentials are available in the 
``credentials.Attributes`` map under the key ``credentials.AttributeKeyADCredentials``. 
For example the SIDs of the users group membership are available and can be used by your application for authorization.

Checking and access the credentials within your application:
```go
// Get a goidentity credentials object from the request's context
creds := goidentity.FromHTTPRequestContext(r)
// Check if it indicates it is authenticated
if creds != nil && creds.Authenticated() {
    // Check for Active Directory attributes
	if ADCredsJSON, ok := creds.Attributes()[credentials.AttributeKeyADCredentials]; ok {
		ADCreds := new(credentials.ADCredentials)
        // Unmarshal the AD attributes
		err := json.Unmarshal([]byte(ADCredsJSON), ADCreds)
		if err == nil {
			// Use validated PAC identity and authorization data.
			userSID := ADCreds.UserSID
			upn := ADCreds.UPN
			groups := ADCreds.GroupMembershipSIDs
			_ = userSID
			_ = upn
			_ = groups
		}
	}
} else {
    // Not authenticated user
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, "Authentication failed")
}
```

`ADCredentials` also exposes the SAM account and DNS domain names, extra and
resource-group SIDs, user-account-control flags, client and device claims,
device identity, S4U delegation path, PAC attributes, requestor SID, and the
ticket authentication time. Optional PAC buffers are represented by nil
pointers or empty values. These fields are only attached after the PAC service
checksum and its client name, authentication time, requestor SID, and extended
UPN/DNS identity have been validated against the decrypted ticket.

#### Generic Kerberised Service - Validating Client Details
To validate the AP_REQ sent by the client on the service side call this method:
```go
import 	"github.com/otuschhoff/gokrb5/v8/service"
s := service.NewSettings(&kt) // kt is a keytab and optional settings can also be provided.
if ok, creds, err := service.VerifyAPREQ(&APReq, s); ok {
        // Perform application specific actions
        // creds object has details about the client identity
}
```
