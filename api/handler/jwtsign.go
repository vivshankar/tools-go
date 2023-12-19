// Package handler is for API handlers
package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/vivshankar/tools-go/pkg/jwt"
)

// JWTSignHandler wraps the HTTP handler
type JWTSignHandler struct{}

type JWTSignRequest struct {
	PrivateKey string                 `json:"key"`
	Payload    interface{}            `json:"payload"`
	Header     map[string]interface{} `json:"header"`
}

// NewJWTSignHandler constructs the object
func NewJWTSignHandler() *JWTSignHandler {
	return &JWTSignHandler{}
}

// HandlerFunc is the HTTP handler
func (h *JWTSignHandler) HandlerFunc(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fmt.Printf("HTTP method is '%s' but expected 'GET'.", r.Method)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("unable to read the request body; err=%s", err),
		})

		return
	}

	var body JWTSignRequest
	err = json.Unmarshal(reqBody, &body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("request body contains invalid input; err=%s", err),
		})

		return
	}

	signedJWT, err := jwt.Sign(r.Context(), []byte(body.PrivateKey), body.Payload, body.Header)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("unable to sign the payload; err=%s", err),
		})

		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"jwt": signedJWT,
	})
}
