package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/vivshankar/tools-go/pkg/oidc"
	"github.com/vivshankar/tools-go/static"
)

const (
	oidcCallbackPath = "/oidc/callback"
	oidcJWKSPath     = "/oidc/jwks.json"
)

// OIDCHandler serves the OIDC authorization code + PKCE tool.
type OIDCHandler struct {
	svc       *oidc.Service
	templates *template.Template
}

// NewOIDCHandler builds the handler. The private_key_jwt key is read from
// oidc.DefaultKeyFile, next to the executable, and generated there if missing. The
// caches stop when ctx ends.
func NewOIDCHandler(ctx context.Context) (*OIDCHandler, error) {
	keyFile, err := oidc.DefaultKeyFile()
	if err != nil {
		return nil, err
	}

	key, created, err := oidc.LoadOrCreateKey(keyFile)
	if err != nil {
		return nil, err
	}

	svc, err := oidc.NewService(ctx, key, nil)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.ParseFS(static.Files, "oidc.html", "oidc_result.html")
	if err != nil {
		return nil, fmt.Errorf("parsing OIDC templates: %w", err)
	}

	if created {
		fmt.Printf("OIDC client key %s generated in %s\n", svc.ServerKeyID(), keyFile)
	} else {
		fmt.Printf("OIDC client key %s loaded from %s\n", svc.ServerKeyID(), keyFile)
	}
	return &OIDCHandler{svc: svc, templates: tmpl}, nil
}

// oidcFormData is the data for the form page.
type oidcFormData struct {
	Error       string
	RedirectURI string
	JWKSURL     string
	KeyID       string

	Issuer               string
	ClientID             string
	AuthMethod           string
	Scopes               string
	AuthorizationDetails string
	UserKey              string
	UserKeyKID           string
	UserKeyAlg           string
}

// oidcResultData is the data for the callback page.
type oidcResultData struct {
	Error  string
	Result *oidc.Result

	// Request is the input to run the flow again, when it is known.
	Request oidc.StartRequest
}

// externalBase returns scheme://host as the browser sees it.
func externalBase(r *http.Request) string {
	scheme := "http"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = strings.TrimSpace(strings.Split(proto, ",")[0])
	} else if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (h *OIDCHandler) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := h.templates.ExecuteTemplate(w, name, data); err != nil {
		fmt.Printf("rendering %s: %v\n", name, err)
	}
}

func (h *OIDCHandler) formData(r *http.Request) oidcFormData {
	base := externalBase(r)
	return oidcFormData{
		RedirectURI: base + oidcCallbackPath,
		JWKSURL:     base + oidcJWKSPath,
		KeyID:       h.svc.ServerKeyID(),
		AuthMethod:  oidc.AuthMethodPublic,
		Scopes:      "openid",
	}
}

// Form shows the input form.
func (h *OIDCHandler) Form(w http.ResponseWriter, r *http.Request) {
	h.render(w, http.StatusOK, "oidc.html", h.formData(r))
}

// Start validates the form and redirects the browser to the authorization endpoint.
func (h *OIDCHandler) Start(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "unable to read the form", http.StatusBadRequest)
		return
	}

	data := h.formData(r)
	if v := strings.TrimSpace(r.PostFormValue("redirect_uri")); v != "" {
		data.RedirectURI = v
	}
	data.Issuer = r.PostFormValue("issuer")
	data.ClientID = r.PostFormValue("client_id")
	data.AuthMethod = r.PostFormValue("auth_method")
	data.Scopes = r.PostFormValue("scopes")
	data.AuthorizationDetails = r.PostFormValue("authorization_details")
	data.UserKey = r.PostFormValue("user_key")
	data.UserKeyKID = r.PostFormValue("user_key_kid")
	data.UserKeyAlg = r.PostFormValue("user_key_alg")

	authURL, err := h.svc.Start(r.Context(), oidc.StartRequest{
		Issuer:               data.Issuer,
		ClientID:             data.ClientID,
		AuthMethod:           data.AuthMethod,
		UserKey:              data.UserKey,
		UserKeyKID:           data.UserKeyKID,
		UserKeyAlg:           data.UserKeyAlg,
		Scopes:               data.Scopes,
		AuthorizationDetails: data.AuthorizationDetails,
		RedirectURI:          data.RedirectURI,
	})
	if err != nil {
		data.Error = err.Error()
		h.render(w, http.StatusBadRequest, "oidc.html", data)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback is the redirect_uri. It exchanges the code and shows the tokens.
func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.Complete(r.Context(), r.URL.Query())
	if err != nil {
		data := oidcResultData{Error: err.Error()}
		if res != nil {
			data.Request = res.Request
		}
		h.render(w, http.StatusBadRequest, "oidc_result.html", data)
		return
	}

	h.render(w, http.StatusOK, "oidc_result.html", oidcResultData{Result: res, Request: res.Request})
}

// JWKS publishes the public key for private_key_jwt.
func (h *OIDCHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.svc.JWKS())
}

// oidcUnavailable answers every OIDC route when the handler could not start.
func oidcUnavailable(err error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, errors.Join(errors.New("OIDC tool is unavailable"), err).Error(), http.StatusInternalServerError)
	}
}
