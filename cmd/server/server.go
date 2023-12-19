package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/vivshankar/tools-go/api"
)

func main() {
	fmt.Println("Dilithium chambers at maximum")
	rootContext, cancel := context.WithCancel(context.Background())

	// build the router
	router := api.NewRouter(rootContext)

	// Spin up the HTTP server
	srv := &http.Server{
		Addr:        ":8080",
		Handler:     http.TimeoutHandler(router, 15*time.Second, "Your request timed out."),
		IdleTimeout: 30 * time.Second,
	}

	err := srv.ListenAndServe()
	if err != nil {
		fmt.Printf("Self-destruct initiated; err=%v", err)
		os.Exit(1)
		return
	}

	// We're done
	cancel()
}
