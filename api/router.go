package api

import (
	"context"

	"github.com/gorilla/mux"
	"github.com/vivshankar/tools-go/api/handler"
)

// NewRouter builds and returns a new router with optional new relic monitoring
func NewRouter(rootContext context.Context) *mux.Router {
	// When StrictSlash == true, if the route path is "/path/", accessing "/path" will perform a redirect to the former and vice versa.
	router := mux.NewRouter().StrictSlash(true)

	handler.NewRouterWithParent(router)
	return router
}
