package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouter_StaticRoutes(t *testing.T) {
	router := NewRouter()

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		expectedHeader string
		expectedLoc    string
	}{
		{
			name:           "Root Route",
			path:           "/",
			expectedStatus: http.StatusOK,
			expectedHeader: "text/html; charset=utf-8",
		},
		{
			name:           "JWT Studio Route",
			path:           "/jwt-studio",
			expectedStatus: http.StatusOK,
			expectedHeader: "text/html; charset=utf-8",
		},
		{
			name:           "Signer Alias",
			path:           "/jwtsigner",
			expectedStatus: http.StatusFound,
			expectedLoc:    "/jwt-studio#signer",
		},
		{
			name:           "Validator Alias",
			path:           "/jwtvalidator",
			expectedStatus: http.StatusFound,
			expectedLoc:    "/jwt-studio#validator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tt.path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectedHeader != "" {
				contentType := rr.Header().Get("Content-Type")
				if contentType != tt.expectedHeader {
					t.Errorf("Expected Content-Type %q, got %q", tt.expectedHeader, contentType)
				}
			}

			if tt.expectedLoc != "" {
				loc := rr.Header().Get("Location")
				if loc != tt.expectedLoc {
					t.Errorf("Expected Location %q, got %q", tt.expectedLoc, loc)
				}
			}
		})
	}
}
