// Package handler is for API handlers
package handler

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/vivshankar/tools-go/static"
)

// NewRouter builds and returns a new router
func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	NewRouterWithParent(router)
	return router
}

// NewRouterWithParent builds and returns a router with paths relative to the router passed in
func NewRouterWithParent(router *mux.Router) {
	// Build the API routers
	jwtapi := router.PathPrefix("/jwt").Subrouter()

	// Build the API paths
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

	// Root path serves index.html
	router.HandleFunc("/", serveHTML("index.html")).Methods(http.MethodGet)
}
