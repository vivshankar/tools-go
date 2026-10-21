// Package handler is for API handlers
package handler

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/vivshankar/tools-go/static"
)

// NewRouter builds and returns a new router
func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	NewRouterWithParent(context.Background(), router)
	return router
}

// NewRouterWithParent builds and returns a router with paths relative to the router passed in.
// ctx bounds the lifetime of background work such as cache cleanup.
func NewRouterWithParent(ctx context.Context, router *mux.Router) {
	// Build the API routers
	jwtapi := router.PathPrefix("/jwt").Subrouter()

	// Build the paths
	jwtapi.HandleFunc("/sign", NewJWTSignHandler().HandlerFunc).Methods(http.MethodPost)

	// serveHTML reads and serves an embedded static HTML file
	serveHTML := func(filename string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			data, err := static.Files.ReadFile(filename)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(data)
		}
	}

	// Primary route: single-page JWT Studio
	router.HandleFunc("/jwt-studio", serveHTML("jwt.html")).Methods(http.MethodGet)

	// Convenience aliases that deep-link to the right tab via hash
	router.HandleFunc("/jwtsigner", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/jwt-studio#signer", http.StatusFound)
	}).Methods(http.MethodGet)

	router.HandleFunc("/jwtvalidator", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/jwt-studio#validator", http.StatusFound)
	}).Methods(http.MethodGet)

	// Shared stylesheet. The content only changes with a new build, so browsers may cache it.
	router.HandleFunc("/static/studio.css", func(w http.ResponseWriter, r *http.Request) {
		data, err := static.Files.ReadFile("studio.css")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	}).Methods(http.MethodGet, http.MethodHead)

	// OIDC authorization code + PKCE tool
	oidcHandler, err := NewOIDCHandler(ctx)
	if err != nil {
		fmt.Printf("OIDC tool disabled; err=%v\n", err)
		unavailable := oidcUnavailable(err)
		router.HandleFunc("/oidc-debugger", unavailable)
		router.HandleFunc("/oidc/{path:.*}", unavailable)
	} else {
		router.HandleFunc("/oidc-debugger", oidcHandler.Form).Methods(http.MethodGet)
		router.HandleFunc("/oidc/start", oidcHandler.Start).Methods(http.MethodPost)
		router.HandleFunc(oidcCallbackPath, oidcHandler.Callback).Methods(http.MethodGet)
		router.HandleFunc(oidcJWKSPath, oidcHandler.JWKS).Methods(http.MethodGet)
	}

	// Root path serves index.html
	router.HandleFunc("/", serveHTML("index.html")).Methods(http.MethodGet)
}
