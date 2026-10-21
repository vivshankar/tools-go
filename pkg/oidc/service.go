package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jellydator/ttlcache/v3"

	auth "github.com/ibm-verify/verify-auth-go"
	vauth "github.com/ibm-verify/verify-auth-go/oauth2"
)

const (
	discoveryTTL = time.Hour
	sessionTTL   = 10 * time.Minute
	httpTimeout  = 10 * time.Second

	// AuthMethodPublic is a public client that sends only its client_id.
	AuthMethodPublic = "public"

	// AuthMethodPrivateKeyJWT authenticates the client with a signed client assertion.
	AuthMethodPrivateKeyJWT = "private_key_jwt"
)

// StartRequest is the user input that begins a flow.
type StartRequest struct {
	// Issuer is an IBM Verify tenant hostname or an OP issuer.
	Issuer   string
	ClientID string

	// AuthMethod is AuthMethodPublic or AuthMethodPrivateKeyJWT.
	AuthMethod string

	// UserKey optionally replaces the server key for private_key_jwt. It is a JWK or PEM.
	UserKey    string
	UserKeyKID string
	UserKeyAlg string

	// Scopes is a space-delimited list.
	Scopes string

	// AuthorizationDetails is a JSON array of authorization_detail objects (RFC 9396).
	AuthorizationDetails string

	// RedirectURI is the redirect_uri registered on the client.
	RedirectURI string
}

// session is what the callback needs to finish the flow.
type session struct {
	req        StartRequest
	client     *vauth.Client
	authResp   *vauth.AuthorizeResponse
	issuer     string
	clientID   string
	authMethod string
	scope      string
}

// ClaimRow is one claim, ready for display.
type ClaimRow struct {
	Name  string
	Value string
	Note  string

	// Multiline is true for structured values, which are shown preformatted.
	Multiline bool
}

// TokenView is a validated token and the outcome of validating it.
type TokenView struct {
	// Title is the heading shown above the token.
	Title string

	// Present is false when the response did not carry this token.
	Present bool
	Raw     string

	// Format is "JWT" or "opaque".
	Format string

	// Method describes how the token was validated.
	Method string

	// Claims is set when validation succeeded.
	Claims []ClaimRow

	// Error is set when validation failed.
	Error string
}

// Result is what the callback page renders.
type Result struct {
	// Request is the input that started the flow, so it can be run again.
	Request StartRequest

	Issuer     string
	ClientID   string
	AuthMethod string

	// ResponseJSON is the token response as returned by the SDK.
	ResponseJSON string

	AccessToken TokenView
	IDToken     TokenView
}

// Service runs the authorization code + PKCE flow.
type Service struct {
	serverKey *jose.JSONWebKey
	hc        *http.Client

	discovery *ttlcache.Cache[string, *vauth.Configuration]
	sessions  *ttlcache.Cache[string, *session]
}

// NewService builds a Service. serverKey is the key used for private_key_jwt unless the
// user supplies one. The caches stop when ctx is cancelled.
func NewService(ctx context.Context, serverKey *jose.JSONWebKey, hc *http.Client) (*Service, error) {
	if hc == nil {
		hc = &http.Client{Timeout: httpTimeout}
	}

	s := &Service{
		serverKey: serverKey,
		hc:        hc,
		discovery: ttlcache.New(
			ttlcache.WithTTL[string, *vauth.Configuration](discoveryTTL),
			ttlcache.WithDisableTouchOnHit[string, *vauth.Configuration](),
		),
		sessions: ttlcache.New(
			ttlcache.WithTTL[string, *session](sessionTTL),
			ttlcache.WithDisableTouchOnHit[string, *session](),
		),
	}

	go s.discovery.Start()
	go s.sessions.Start()
	go func() {
		<-ctx.Done()
		s.discovery.Stop()
		s.sessions.Stop()
	}()

	return s, nil
}

// ServerKeyID is the kid of the server key.
func (s *Service) ServerKeyID() string { return s.serverKey.KeyID }

// JWKS returns the public keys that verify the server's client assertions.
func (s *Service) JWKS() jose.JSONWebKeySet { return PublicJWKS(s.serverKey) }

// configuration returns the cached discovery document for the issuer.
func (s *Service) configuration(ctx context.Context, issuer string) (*vauth.Configuration, error) {
	if item := s.discovery.Get(issuer); item != nil {
		return item.Value(), nil
	}

	cfg, err := vauth.Discover(ctx, issuer, s.hc)
	if err != nil {
		return nil, fmt.Errorf("discovering %s: %w", issuer, err)
	}

	s.discovery.Set(issuer, cfg, discoveryTTL)
	return cfg, nil
}

func parseAuthorizationDetails(raw string) ([]map[string]any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var details []map[string]any
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		return nil, fmt.Errorf("authorization_details must be a JSON array of objects: %w", err)
	}
	return details, nil
}

func (s *Service) clientAuth(req StartRequest, cfg *vauth.Configuration) (vauth.ClientAuth, string, error) {
	switch req.AuthMethod {
	case AuthMethodPublic, "":
		return &vauth.ClientSecretPost{ClientID: req.ClientID}, AuthMethodPublic, nil
	case AuthMethodPrivateKeyJWT:
		key := s.serverKey
		if strings.TrimSpace(req.UserKey) != "" {
			var err error
			key, err = ParseKey([]byte(req.UserKey), strings.TrimSpace(req.UserKeyKID), strings.TrimSpace(req.UserKeyAlg))
			if err != nil {
				return nil, "", fmt.Errorf("client key: %w", err)
			}
		}
		return &vauth.PrivateKeyJWT{Configuration: cfg, ClientID: req.ClientID, PrivateKeyJWK: key}, AuthMethodPrivateKeyJWT, nil
	default:
		return nil, "", fmt.Errorf("unsupported client authentication method %q", req.AuthMethod)
	}
}

// Start performs discovery and returns the authorization URL to send the browser to.
func (s *Service) Start(ctx context.Context, req StartRequest) (string, error) {
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.ClientID == "" {
		return "", errors.New("client_id is required")
	}
	if strings.TrimSpace(req.RedirectURI) == "" {
		return "", errors.New("redirect_uri is required")
	}

	issuer, err := NormalizeIssuer(req.Issuer)
	if err != nil {
		return "", err
	}

	details, err := parseAuthorizationDetails(req.AuthorizationDetails)
	if err != nil {
		return "", err
	}

	cfg, err := s.configuration(ctx, issuer)
	if err != nil {
		return "", err
	}

	clientAuth, method, err := s.clientAuth(req, cfg)
	if err != nil {
		return "", err
	}

	scopes := strings.Fields(req.Scopes)
	client, err := vauth.NewClient(clientAuth, cfg,
		vauth.WithHTTPClient(s.hc),
		vauth.WithRedirectURL(req.RedirectURI),
		vauth.WithScopes(scopes...),
		vauth.WithAuthorizationDetails(details),
	)
	if err != nil {
		return "", err
	}

	authResp, err := client.AuthorizeWithBrowserFlow(ctx, nil)
	if err != nil {
		return "", err
	}

	s.sessions.Set(authResp.State, &session{
		req:        req,
		client:     client,
		authResp:   authResp,
		issuer:     cfg.Issuer,
		clientID:   req.ClientID,
		authMethod: method,
		scope:      strings.Join(scopes, " "),
	}, sessionTTL)

	return authResp.AuthCodeURL, nil
}

// Complete finishes the flow from the query string the OP sent to the redirect_uri.
// A state is single use. When the state is known but the code exchange fails, the
// returned Result holds only the Request, so the flow can be run again.
func (s *Service) Complete(ctx context.Context, query url.Values) (*Result, error) {
	var sess *session
	if state := query.Get("state"); state != "" {
		if item, ok := s.sessions.GetAndDelete(state); ok {
			sess = item.Value()
		}
	}

	if sess == nil {
		if code := query.Get("error"); code != "" {
			return nil, &auth.Error{Code: code, Description: query.Get("error_description")}
		}
		return nil, &auth.Error{
			Code:        "unknown_state",
			Description: "the state is unknown or has expired; start the flow again",
		}
	}

	tr, err := sess.client.TokenWithAuthCode(ctx, sess.authResp, query)
	if err != nil {
		return &Result{Request: sess.req}, err
	}

	resp, err := json.MarshalIndent(tr, "", "  ")
	if err != nil {
		return &Result{Request: sess.req}, err
	}

	res := &Result{
		Request:      sess.req,
		Issuer:       sess.issuer,
		ClientID:     sess.clientID,
		AuthMethod:   sess.authMethod,
		ResponseJSON: string(resp),
	}

	res.AccessToken = validateAccessToken(ctx, sess.client, tr.AccessToken)
	res.AccessToken.Title = "Access token"
	res.IDToken = validateIDToken(ctx, sess.client, tr.IDToken, sess.clientID)
	res.IDToken.Title = "ID token"
	return res, nil
}

func tokenFormat(raw string) string {
	if strings.Count(raw, ".") == 2 {
		return "JWT"
	}
	return "opaque"
}

func validateAccessToken(ctx context.Context, c *vauth.Client, raw string) TokenView {
	v := TokenView{Present: raw != "", Raw: raw}
	if !v.Present {
		return v
	}

	v.Format = tokenFormat(raw)
	if v.Format == "JWT" {
		v.Method = "Signature verified against the JWKS; iss, exp and iat checked"
	} else {
		v.Method = "Validated with the introspection endpoint"
	}

	claims, err := c.ValidateAccessToken(ctx, raw, "")
	if err != nil {
		v.Error = err.Error()
		return v
	}

	m := map[string]any{}
	put(m, "iss", claims.Issuer)
	put(m, "sub", claims.Subject)
	put(m, "aud", claims.Audience)
	put(m, "scope", claims.Scope)
	put(m, "client_id", claims.ClientID)
	put(m, "username", claims.Username)
	put(m, "token_type", claims.TokenType)
	put(m, "jti", claims.JWTID)
	putTime(m, "exp", claims.Expiry)
	putTime(m, "iat", claims.IssuedAt)
	putTime(m, "nbf", claims.NotBefore)
	for k, val := range claims.Extra {
		m[k] = val
	}

	v.Claims = claimRows(m)
	return v
}

func validateIDToken(ctx context.Context, c *vauth.Client, raw, clientID string) TokenView {
	v := TokenView{Present: raw != "", Raw: raw}
	if !v.Present {
		return v
	}

	v.Format = tokenFormat(raw)
	v.Method = "Signature verified against the JWKS; iss, aud, exp and iat checked"

	claims, err := c.ValidateIDToken(ctx, raw, clientID)
	if err != nil {
		v.Error = err.Error()
		return v
	}

	m := map[string]any{}
	put(m, "iss", claims.Issuer)
	put(m, "sub", claims.Subject)
	put(m, "aud", claims.Audience)
	put(m, "nonce", claims.Nonce)
	putTime(m, "exp", claims.Expiry)
	putTime(m, "iat", claims.IssuedAt)
	for k, val := range claims.Extra {
		m[k] = val
	}

	v.Claims = claimRows(m)
	return v
}
