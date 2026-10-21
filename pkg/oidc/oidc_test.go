package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestNormalizeIssuer(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"bare hostname", "acme.verify.ibm.com", "https://acme.verify.ibm.com/oauth2", false},
		{"hostname with spaces", "  acme.verify.ibm.com  ", "https://acme.verify.ibm.com/oauth2", false},
		{"hostname with trailing slash", "acme.verify.ibm.com/", "https://acme.verify.ibm.com/oauth2", false},
		{"hostname with path", "op.example.com/custom", "https://op.example.com/custom", false},
		{"issuer URL", "https://op.example.com/other", "https://op.example.com/other", false},
		{"issuer URL trailing slash", "https://op.example.com/oauth2/", "https://op.example.com/oauth2", false},
		{"issuer with scheme and no path is kept as-is", "https://op.example.com", "https://op.example.com", false},
		{"http issuer", "http://localhost:9000/op", "http://localhost:9000/op", false},
		{"empty", "   ", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeIssuer(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func pemOf(t *testing.T, typ string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestParseKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)

	jwkBytes, err := json.Marshal(jose.JSONWebKey{Key: rsaKey, KeyID: "my-kid", Algorithm: "PS256"})
	require.NoError(t, err)
	publicOnly, err := json.Marshal(jose.JSONWebKey{Key: &rsaKey.PublicKey})
	require.NoError(t, err)

	rsaPEM := pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))

	tests := []struct {
		name    string
		data    []byte
		kid     string
		alg     string
		wantAlg string
		wantKID string // empty means "the thumbprint"
		wantErr bool
	}{
		{"RSA PKCS#1 PEM", rsaPEM, "", "", "RS256", "", false},
		{"RSA PKCS#8 PEM", pemOf(t, "PRIVATE KEY", pkcs8), "", "", "RS256", "", false},
		{"EC PEM defaults to the curve algorithm", pemOf(t, "EC PRIVATE KEY", sec1), "", "", "ES384", "", false},
		{"explicit kid and alg win", rsaPEM, "k1", "PS256", "PS256", "k1", false},
		{"JWK keeps its kid and alg", jwkBytes, "", "", "PS256", "my-kid", false},
		{"JWK overridden by explicit values", jwkBytes, "other", "RS512", "RS512", "other", false},
		{"public JWK is rejected", publicOnly, "", "", "", "", true},
		{"public PEM is rejected", pemOf(t, "PUBLIC KEY", []byte{1, 2, 3}), "", "", "", "", true},
		{"garbage", []byte("not a key"), "", "", "", "", true},
		{"empty", []byte("  "), "", "", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKey(tt.data, tt.kid, tt.alg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantAlg, got.Algorithm)
			require.Equal(t, "sig", got.Use)
			if tt.wantKID != "" {
				require.Equal(t, tt.wantKID, got.KeyID)
			} else {
				require.NotEmpty(t, got.KeyID)
			}
		})
	}
}

func TestParseKey_ThumbprintIsStable(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	data := pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))

	a, err := ParseKey(data, "", "")
	require.NoError(t, err)
	b, err := ParseKey(data, "", "")
	require.NoError(t, err)
	require.Equal(t, a.KeyID, b.KeyID)
}

func TestGenerateKey_HasUniqueKeyID(t *testing.T) {
	a, err := GenerateKey()
	require.NoError(t, err)
	b, err := GenerateKey()
	require.NoError(t, err)

	_, err = uuid.Parse(a.KeyID)
	require.NoError(t, err, "kid should be a UUID")
	require.NotEqual(t, a.KeyID, b.KeyID)
	require.Equal(t, "RS256", a.Algorithm)
	require.Equal(t, "sig", a.Use)
}

func TestPublicJWKS_HasNoPrivateMaterial(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	out, err := json.Marshal(PublicJWKS(key))
	require.NoError(t, err)

	var set map[string][]map[string]any
	require.NoError(t, json.Unmarshal(out, &set))
	require.Len(t, set["keys"], 1)

	jwk := set["keys"][0]
	require.Equal(t, key.KeyID, jwk["kid"])
	require.Equal(t, "RS256", jwk["alg"])
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		require.NotContains(t, jwk, private)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	t.Run("creates the key and its directory when the file is missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nested", "client.jwk")

		key, created, err := LoadOrCreateKey(path)
		require.NoError(t, err)
		require.True(t, created)
		require.NotEmpty(t, key.KeyID)

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("reloads the same key on the next start", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "client.jwk")

		first, created, err := LoadOrCreateKey(path)
		require.NoError(t, err)
		require.True(t, created)

		second, created, err := LoadOrCreateKey(path)
		require.NoError(t, err)
		require.False(t, created)
		require.Equal(t, first.KeyID, second.KeyID)
		require.Equal(t, first.Algorithm, second.Algorithm)
	})

	t.Run("a corrupt file is an error and is left untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "client.jwk")
		require.NoError(t, os.WriteFile(path, []byte("garbage"), 0o600))

		_, _, err := LoadOrCreateKey(path)
		require.Error(t, err)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "garbage", string(data))
	})
}

func TestDefaultKeyFile_IsNextToTheExecutable(t *testing.T) {
	path, err := DefaultKeyFile()
	require.NoError(t, err)

	exe, err := os.Executable()
	require.NoError(t, err)
	require.Equal(t, filepath.Dir(exe), filepath.Dir(path))
	require.Equal(t, "client.jwk", filepath.Base(path))
}

func TestParseAuthorizationDetails(t *testing.T) {
	got, err := parseAuthorizationDetails(`[{"type":"payment_initiation","actions":["initiate"]}]`)
	require.NoError(t, err)
	require.Equal(t, []map[string]any{{"type": "payment_initiation", "actions": []any{"initiate"}}}, got)

	got, err = parseAuthorizationDetails("   ")
	require.NoError(t, err)
	require.Nil(t, got)

	_, err = parseAuthorizationDetails(`{"type":"payment_initiation"}`)
	require.Error(t, err, "an object is not an array")

	_, err = parseAuthorizationDetails(`[1,2]`)
	require.Error(t, err, "elements must be objects")

	_, err = parseAuthorizationDetails(`not json`)
	require.Error(t, err)
}
