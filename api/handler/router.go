// Package handler is for API handlers
package handler

import (
	"net/http"

	"github.com/gorilla/mux"
)

// NewRouter builds and returns a new router
func NewRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)
	NewRouterWithParent(router)
	return router
}

// NewRouterWithParent builds and returns a router with paths relative to the router passed in
func NewRouterWithParent(router *mux.Router) {
	// Build the routers
	jwtapi := router.PathPrefix("/jwt").Subrouter()

	// Build the paths
	jwtapi.HandleFunc("/sign", NewJWTSignHandler().HandlerFunc).Methods(http.MethodPost)
}
