package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vivshankar/tools-go/api"
	"github.com/vivshankar/tools-go/pkg/oidc"
)

// shutdownTimeout is how long in-flight requests get to finish after a signal.
const shutdownTimeout = 10 * time.Second

func main() {
	generateKey := flag.Bool("generate-key", false,
		"create the OIDC client key next to the executable if it is missing, then exit")
	flag.Parse()

	if *generateKey {
		path, err := oidc.DefaultKeyFile()
		if err == nil {
			var created bool
			_, created, err = oidc.LoadOrCreateKey(path)
			if err == nil {
				fmt.Printf("OIDC client key at %s (created=%t)\n", path, created)
			}
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return
	}

	fmt.Println("Dilithium chambers at maximum")

	// rootContext ends on Ctrl-C (SIGINT) or SIGTERM, for example from docker stop
	rootContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// build the router
	router := api.NewRouter(rootContext)

	// Spin up the HTTP server
	srv := &http.Server{
		Addr:        ":8080",
		Handler:     http.TimeoutHandler(router, 15*time.Second, "Your request timed out."),
		IdleTimeout: 30 * time.Second,
	}

	// Shut down gracefully once a signal arrives
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-rootContext.Done()

		fmt.Println("Shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			fmt.Printf("Shutdown error; err=%v\n", err)
		}
	}()

	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("Self-destruct initiated; err=%v\n", err)
		os.Exit(1)
	}

	// ListenAndServe returns as soon as Shutdown starts, so wait for it to finish
	<-shutdownDone
}
