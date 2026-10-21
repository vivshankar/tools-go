package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

// fakeOP is a minimal OpenID provider: discovery, JWKS and a token endpoint
// that issues signed JWTs.
type fakeOP struct {
	*httptest.Server
	signer jose.Signer
	jwks   jose.JSONWebKeySet

	mu             sync.Mutex
	discoveryCalls int
	tokenForm      url.Values
	tokenAuthz     string

	// accessToken overrides the issued access token (for opaque tokens).
	accessToken string
}

func newFakeOP(t *testing.T) *fakeOP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: key, KeyID: "op-key", Algorithm: string(jose.RS256), Use: "sig"}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk},
		(&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	op := &fakeOP{signer: signer, jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk.Public()}}}
	mux := http.NewServeMux()
	op.Server = httptest.NewServer(mux)
	t.Cleanup(op.Close)

	issuer := op.URL + "/oauth2"

	mux.HandleFunc("/oauth2/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		op.mu.Lock()
		op.discoveryCalls++
		op.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
		})
	})

	mux.HandleFunc("/oauth2/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(op.jwks)
	})

	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		op.mu.Lock()
		op.tokenForm = r.PostForm
		op.tokenAuthz = r.Header.Get("Authorization")
		override := op.accessToken
		op.mu.Unlock()

		now := time.Now()
		access := override
		if access == "" {
			access = op.sign(t, map[string]any{
				"iss": issuer, "sub": "user-1", "aud": "api",
				"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "jti": "at-1",
				"scope": "openid profile", "custom": "value",
				"authorization_details": []any{map[string]any{"type": "payment_initiation"}},
			})
		}
		id := op.sign(t, map[string]any{
			"iss": issuer, "sub": "user-1", "aud": r.PostForm.Get("client_id"),
			"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nonce": "n-1",
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": access, "token_type": "Bearer", "expires_in": 3600,
			"scope": "openid profile", "id_token": id, "grant_id": "g-1",
			"authorization_details": []any{map[string]any{"type": "payment_initiation"}},
		})
	})

	return op
}

func (op *fakeOP) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := josejwt.Signed(op.signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return tok
}

func (op *fakeOP) calls() int {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.discoveryCalls
}

func (op *fakeOP) lastToken() (url.Values, string) {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.tokenForm, op.tokenAuthz
}

func newOIDCRouter(t *testing.T) *mux.Router {
	t.Helper()
	t.Chdir(t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	router := mux.NewRouter().StrictSlash(true)
	NewRouterWithParent(ctx, router)
	return router
}

func do(router http.Handler, method, target string, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// signIn posts the form and returns the authorize URL the browser is sent to.
func signIn(t *testing.T, router http.Handler, form url.Values) *url.URL {
	t.Helper()
	rr := do(router, http.MethodPost, "/oidc/start", form)
	require.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
	u, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	return u
}

func callbackFor(authorize *url.URL, code string) string {
	q := url.Values{"code": {code}, "state": {authorize.Query().Get("state")}}
	return "/oidc/callback?" + q.Encode()
}

func baseForm(op *fakeOP) url.Values {
	return url.Values{
		"issuer":       {op.URL + "/oauth2"},
		"client_id":    {"tools-client"},
		"auth_method":  {"public"},
		"redirect_uri": {"http://tools.test/oidc/callback"},
		"scopes":       {"openid profile"},
	}
}

func TestOIDC_PublicClientFlow(t *testing.T) {
	op := newFakeOP(t)
	router := newOIDCRouter(t)

	form := baseForm(op)
	form.Set("authorization_details", `[{"type":"payment_initiation","actions":["initiate"]}]`)
	authorize := signIn(t, router, form)

	// The browser is sent to the OP's authorization endpoint with PKCE and RAR.
	require.Equal(t, op.URL+"/oauth2/authorize", authorize.Scheme+"://"+authorize.Host+authorize.Path)
	q := authorize.Query()
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "tools-client", q.Get("client_id"))
	require.Equal(t, "http://tools.test/oidc/callback", q.Get("redirect_uri"))
	require.Equal(t, "openid profile", q.Get("scope"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.NotEmpty(t, q.Get("code_challenge"))
	require.JSONEq(t, `[{"type":"payment_initiation","actions":["initiate"]}]`, q.Get("authorization_details"))
	require.False(t, q.Has("client_assertion"))

	// The callback exchanges the code and renders the tokens.
	rr := do(router, http.MethodGet, callbackFor(authorize, "the-code"), nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	require.Equal(t, "text/html; charset=utf-8", rr.Header().Get("Content-Type"))

	body := rr.Body.String()
	require.Contains(t, body, "Token response")
	require.Contains(t, body, "payment_initiation") // authorization_details in the response
	require.Contains(t, body, "Signature verified against the JWKS")
	require.Contains(t, body, "user-1") // sub
	require.Contains(t, body, "custom") // non-standard claim
	require.Contains(t, body, "Validated")
	require.NotContains(t, body, "Not validated")

	tokenForm, authz := op.lastToken()
	require.Equal(t, "authorization_code", tokenForm.Get("grant_type"))
	require.Equal(t, "the-code", tokenForm.Get("code"))
	require.Equal(t, "tools-client", tokenForm.Get("client_id"))
	require.NotEmpty(t, tokenForm.Get("code_verifier"))
	require.Equal(t, "http://tools.test/oidc/callback", tokenForm.Get("redirect_uri"))
	require.JSONEq(t, `[{"type":"payment_initiation","actions":["initiate"]}]`, tokenForm.Get("authorization_details"))
	require.False(t, tokenForm.Has("client_assertion"))
	require.Empty(t, authz, "credentials must be in the body, not an Authorization header")
}

func TestOIDC_PrivateKeyJWTUsesServerKey(t *testing.T) {
	op := newFakeOP(t)
	router := newOIDCRouter(t)

	form := baseForm(op)
	form.Set("auth_method", "private_key_jwt")
	authorize := signIn(t, router, form)

	// The assertion must never travel through the browser.
	require.False(t, authorize.Query().Has("client_assertion"))
	require.False(t, authorize.Query().Has("client_assertion_type"))

	rr := do(router, http.MethodGet, callbackFor(authorize, "c"), nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	tokenForm, authz := op.lastToken()
	require.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", tokenForm.Get("client_assertion_type"))
	require.Empty(t, authz)

	// The assertion verifies against the JWKS published by tools.
	jwksRR := do(router, http.MethodGet, "/oidc/jwks.json", nil)
	require.Equal(t, http.StatusOK, jwksRR.Code)
	var jwks jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(jwksRR.Body.Bytes(), &jwks))
	require.Len(t, jwks.Keys, 1)
	require.True(t, jwks.Keys[0].IsPublic())

	parsed, err := josejwt.ParseSigned(tokenForm.Get("client_assertion"), []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Equal(t, jwks.Keys[0].KeyID, parsed.Headers[0].KeyID)

	var claims map[string]any
	require.NoError(t, parsed.Claims(jwks.Keys[0], &claims))
	require.Equal(t, "tools-client", claims["iss"])
	require.Equal(t, "tools-client", claims["sub"])
}

func TestOIDC_PrivateKeyJWTWithUserKey(t *testing.T) {
	op := newFakeOP(t)
	router := newOIDCRouter(t)

	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwkJSON, err := json.Marshal(jose.JSONWebKey{Key: userKey, KeyID: "mine", Algorithm: "RS256"})
	require.NoError(t, err)

	form := baseForm(op)
	form.Set("auth_method", "private_key_jwt")
	form.Set("user_key", string(jwkJSON))
	authorize := signIn(t, router, form)

	rr := do(router, http.MethodGet, callbackFor(authorize, "c"), nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	tokenForm, _ := op.lastToken()
	parsed, err := josejwt.ParseSigned(tokenForm.Get("client_assertion"), []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Equal(t, "mine", parsed.Headers[0].KeyID)
	require.NoError(t, parsed.Claims(&userKey.PublicKey, &map[string]any{}))
}

func TestOIDC_OpaqueAccessTokenFailsIntrospectionWithoutEndpoint(t *testing.T) {
	op := newFakeOP(t)
	op.accessToken = "opaque-token-value"
	router := newOIDCRouter(t)

	authorize := signIn(t, router, baseForm(op))
	rr := do(router, http.MethodGet, callbackFor(authorize, "c"), nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	body := rr.Body.String()
	require.Contains(t, body, "opaque-token-value", "the raw response is still shown")
	require.Contains(t, body, "introspection endpoint")
	require.Contains(t, body, "Not validated")
}

func TestOIDC_DiscoveryIsCachedPerIssuer(t *testing.T) {
	op := newFakeOP(t)
	router := newOIDCRouter(t)

	signIn(t, router, baseForm(op))
	signIn(t, router, baseForm(op))
	require.Equal(t, 1, op.calls())

	// Case and a trailing slash still resolve to the same cache entry.
	form := baseForm(op)
	form.Set("issuer", op.URL+"/oauth2/")
	signIn(t, router, form)
	require.Equal(t, 1, op.calls())
}

func TestOIDC_StateIsSingleUse(t *testing.T) {
	op := newFakeOP(t)
	router := newOIDCRouter(t)

	authorize := signIn(t, router, baseForm(op))
	target := callbackFor(authorize, "c")

	require.Equal(t, http.StatusOK, do(router, http.MethodGet, target, nil).Code)

	rr := do(router, http.MethodGet, target, nil)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "unknown_state")
}

func TestOIDC_CallbackErrors(t *testing.T) {
	op := newFakeOP(t)
	router := newOIDCRouter(t)

	t.Run("unknown state", func(t *testing.T) {
		rr := do(router, http.MethodGet, "/oidc/callback?code=c&state=nope", nil)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "unknown_state")
	})

	t.Run("OP error response", func(t *testing.T) {
		authorize := signIn(t, router, baseForm(op))
		q := url.Values{
			"error":             {"access_denied"},
			"error_description": {"the user said no"},
			"state":             {authorize.Query().Get("state")},
		}
		rr := do(router, http.MethodGet, "/oidc/callback?"+q.Encode(), nil)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "access_denied")
		require.Contains(t, rr.Body.String(), "the user said no")
	})

	t.Run("OP error without a usable state", func(t *testing.T) {
		rr := do(router, http.MethodGet, "/oidc/callback?error=access_denied&error_description=denied", nil)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "access_denied")
	})

	t.Run("no query at all", func(t *testing.T) {
		rr := do(router, http.MethodGet, "/oidc/callback", nil)
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestOIDC_StartValidation(t *testing.T) {
	op := newFakeOP(t)
	router := newOIDCRouter(t)

	tests := []struct {
		name    string
		mutate  func(url.Values)
		wantMsg string
	}{
		{"missing client_id", func(v url.Values) { v.Del("client_id") }, "client_id is required"},
		{"missing issuer", func(v url.Values) { v.Del("issuer") }, "issuer is required"},
		{"authorization_details not an array", func(v url.Values) { v.Set("authorization_details", `{"type":"x"}`) }, "authorization_details must be a JSON array"},
		{"invalid user key", func(v url.Values) {
			v.Set("auth_method", "private_key_jwt")
			v.Set("user_key", "garbage")
		}, "client key"},
		{"unreachable issuer", func(v url.Values) { v.Set("issuer", "http://127.0.0.1:1/oauth2") }, "discovering"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := baseForm(op)
			tt.mutate(form)

			rr := do(router, http.MethodPost, "/oidc/start", form)
			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Contains(t, rr.Body.String(), tt.wantMsg)
			// The form is shown again with what was typed.
			require.Contains(t, rr.Body.String(), "Authorization code flow with PKCE")
		})
	}
}

func TestOIDC_FormPage(t *testing.T) {
	router := newOIDCRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/oidc-debugger", nil)
	req.Host = "tools.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	require.Contains(t, body, "https://tools.example.com/oidc/callback")
	require.Contains(t, body, "https://tools.example.com/oidc/jwks.json")
}

func TestOIDC_SharedStylesheet(t *testing.T) {
	router := NewRouter()

	rr := do(router, http.MethodGet, "/static/studio.css", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
	require.Contains(t, rr.Header().Get("Cache-Control"), "max-age")
	require.Contains(t, rr.Body.String(), ".card")

	for _, page := range []string{"/jwt-studio", "/oidc-debugger"} {
		body := do(router, http.MethodGet, page, nil).Body.String()
		require.Contains(t, body, `href="/static/studio.css"`, page)
		require.NotContains(t, body, "<style", page)
	}
}

// rerunForm reads the "Run again" form from a callback page.
func rerunForm(t *testing.T, body string) url.Values {
	t.Helper()
	require.Contains(t, body, `<button class="btn btn-primary" type="submit">Run again</button>`)

	form := url.Values{}
	for _, m := range regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`).FindAllStringSubmatch(body, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	return form
}

func TestOIDC_RunAgain(t *testing.T) {
	op := newFakeOP(t)
	router := newOIDCRouter(t)

	form := baseForm(op)
	form.Set("auth_method", "private_key_jwt")
	form.Set("authorization_details", `[{"type":"payment_initiation","actions":["initiate"]}]`)
	first := signIn(t, router, form)

	rr := do(router, http.MethodGet, callbackFor(first, "c1"), nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// Posting the page's "Run again" form repeats the flow with the same settings.
	second := signIn(t, router, rerunForm(t, rr.Body.String()))

	a, b := first.Query(), second.Query()
	require.NotEqual(t, a.Get("state"), b.Get("state"), "a new state is used")
	require.NotEqual(t, a.Get("code_challenge"), b.Get("code_challenge"), "a new PKCE verifier is used")
	for _, name := range []string{"client_id", "redirect_uri", "scope", "authorization_details", "response_type"} {
		require.Equal(t, a.Get(name), b.Get(name), name)
	}
	require.Equal(t, first.Path, second.Path)

	rr = do(router, http.MethodGet, callbackFor(second, "c2"), nil)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	tokenForm, _ := op.lastToken()
	require.Equal(t, "c2", tokenForm.Get("code"))
	require.NotEmpty(t, tokenForm.Get("client_assertion"), "private_key_jwt is kept")
}

func TestOIDC_RunAgainAfterFailure(t *testing.T) {
	op := newFakeOP(t)
	router := newOIDCRouter(t)

	authorize := signIn(t, router, baseForm(op))
	q := url.Values{"error": {"access_denied"}, "state": {authorize.Query().Get("state")}}
	rr := do(router, http.MethodGet, "/oidc/callback?"+q.Encode(), nil)
	require.Equal(t, http.StatusBadRequest, rr.Code)

	signIn(t, router, rerunForm(t, rr.Body.String()))
}

func TestOIDC_NoRunAgainWithoutAKnownFlow(t *testing.T) {
	router := newOIDCRouter(t)

	rr := do(router, http.MethodGet, "/oidc/callback?code=c&state=nope", nil)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.NotContains(t, rr.Body.String(), "Run again")
}
