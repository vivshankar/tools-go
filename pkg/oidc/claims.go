package oidc

import (
	"encoding/json"
	"sort"
	"time"
)

// standardClaimOrder lists claims that are shown first, in this order.
var standardClaimOrder = []string{
	"iss", "sub", "aud", "client_id", "username", "scope", "token_type",
	"exp", "iat", "nbf", "nonce", "jti",
}

var timeClaims = map[string]bool{"exp": true, "iat": true, "nbf": true}

// put stores v under name unless it is empty.
func put(m map[string]any, name string, v any) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return
		}
	case []string:
		if len(t) == 0 {
			return
		}
	}
	m[name] = v
}

func putTime(m map[string]any, name string, t *time.Time) {
	if t != nil {
		m[name] = t.Unix()
	}
}

// claimRows orders claims for display: standard claims first, then the rest by name.
func claimRows(m map[string]any) []ClaimRow {
	var rows []ClaimRow
	seen := map[string]bool{}

	add := func(name string) {
		v, ok := m[name]
		if !ok || seen[name] {
			return
		}
		seen[name] = true
		_, isString := v.(string)
		rows = append(rows, ClaimRow{
			Name:      name,
			Value:     formatClaim(v),
			Note:      claimNote(name, v),
			Multiline: !isString,
		})
	}

	for _, name := range standardClaimOrder {
		add(name)
	}

	var rest []string
	for name := range m {
		if !seen[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		add(name)
	}

	return rows
}

func formatClaim(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "unprintable value"
	}
	return string(b)
}

func claimNote(name string, v any) string {
	if !timeClaims[name] {
		return ""
	}

	switch n := v.(type) {
	case int64:
		return time.Unix(n, 0).UTC().Format(time.RFC3339)
	case float64:
		return time.Unix(int64(n), 0).UTC().Format(time.RFC3339)
	}
	return ""
}
