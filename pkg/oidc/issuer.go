// Package oidc implements an OpenID Connect authorization code + PKCE flow on top of
// the IBM Verify auth SDK.
package oidc

import (
	"errors"
	"net/url"
	"strings"
)

// defaultIssuerPath is the issuer path of an IBM Verify tenant.
const defaultIssuerPath = "/oauth2"

// NormalizeIssuer turns user input into an issuer URL.
//
//   - A bare tenant hostname such as "acme.verify.ibm.com" becomes
//     "https://acme.verify.ibm.com/oauth2".
//   - Input with a scheme is treated as the issuer and used as-is, minus any
//     trailing slash.
func NormalizeIssuer(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", errors.New("an IBM Verify tenant hostname or an issuer is required")
	}

	hasScheme := strings.Contains(s, "://")
	if !hasScheme {
		s = "https://" + s
	}

	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", errors.New("the tenant hostname or issuer is not a valid URL")
	}

	if !hasScheme && strings.Trim(u.Path, "/") == "" {
		u.Path = defaultIssuerPath
	}

	return strings.TrimRight(u.String(), "/"), nil
}
