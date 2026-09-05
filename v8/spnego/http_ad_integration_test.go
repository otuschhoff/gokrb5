package spnego

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/test/ad"
	"github.com/stretchr/testify/assert"
)

// TestSPNEGO_AD_EndToEnd authenticates the discovered AD user against a gokrb5
// HTTP acceptor keyed with the host keytab and checks the PAC-derived identity.
func TestSPNEGO_AD_EndToEnd(t *testing.T) {
	env := ad.Environment(t)
	spn, err := env.ServiceSPN()
	if err != nil {
		t.Fatal(err)
	}

	l := log.New(os.Stderr, "SPNEGO AD: ", log.LstdFlags)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := goidentity.FromHTTPRequestContext(r)
		fmt.Fprintf(w, "%s@%s|%d", id.UserName(), id.Domain(), len(id.AuthzAttributes()))
	})
	srv := httptest.NewServer(SPNEGOKRB5Authenticate(inner, env.Keytab, service.Logger(l)))
	defer srv.Close()

	cl := client.NewWithPassword(env.User, env.UserRealm, env.Password, env.Config, client.Logger(l), client.DisablePAReqEncPARep(true))
	if err := cl.Login(); err != nil {
		t.Fatalf("Error on login: %v", err)
	}
	r, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := NewClient(cl, srv.Client(), spn).Do(r)
	if err != nil {
		t.Fatalf("SPNEGO request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "acceptor should authenticate the AD user: %s", body)

	parts := strings.Split(string(body), "|")
	if assert.Len(t, parts, 2) {
		assert.True(t, strings.EqualFold(env.User+"@"+env.UserRealm, parts[0]), "authenticated identity %q should match %s@%s", parts[0], env.User, env.UserRealm)
		assert.NotEqual(t, "0", parts[1], "PAC group SIDs should be exposed to the handler")
	}
}
