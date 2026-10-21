package oidc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// keyFileName is the name of the server's private_key_jwt key file.
const keyFileName = "client.jwk"

// DefaultKeyFile is the path of the server key: next to the running executable.
func DefaultKeyFile() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locating the executable: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), keyFileName), nil
}

// LoadOrCreateKey reads the private JWK at path. If the file does not exist, it
// generates a key and writes it there (mode 0600), creating the directory as needed.
// An existing file that cannot be parsed is an error and is never overwritten.
func LoadOrCreateKey(path string) (key *jose.JSONWebKey, created bool, err error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if key, err = ParseKey(data, "", ""); err != nil {
			return nil, false, fmt.Errorf("reading key file %s: %w", path, err)
		}
		return key, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("reading key file %s: %w", path, err)
	}

	if key, err = GenerateKey(); err != nil {
		return nil, false, err
	}
	if data, err = json.MarshalIndent(key, "", "  "); err != nil {
		return nil, false, fmt.Errorf("encoding key: %w", err)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("creating key directory: %w", err)
	}
	if err = os.WriteFile(path, data, 0o600); err != nil {
		return nil, false, fmt.Errorf("writing key file %s: %w", path, err)
	}
	return key, true, nil
}

// GenerateKey creates a new RSA 2048 signing key (RS256) with a unique, random kid.
func GenerateKey() (*jose.JSONWebKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return ParseKeyFromCrypto(k, uuid.NewString(), "")
}

// ParseKeyFromCrypto wraps a private key and fills in the kid, alg and use values.
// A blank kid defaults to the RFC 7638 thumbprint and a blank alg to a value
// that suits the key type.
func ParseKeyFromCrypto(key crypto.PrivateKey, kid, alg string) (*jose.JSONWebKey, error) {
	jwk := &jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: alg, Use: "sig"}
	if jwk.IsPublic() {
		return nil, errors.New("the key must be a private key")
	}

	if jwk.Algorithm == "" {
		a, err := defaultAlgorithm(key)
		if err != nil {
			return nil, err
		}
		jwk.Algorithm = a
	}

	if jwk.KeyID == "" {
		tp, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("computing key thumbprint: %w", err)
		}
		jwk.KeyID = base64.RawURLEncoding.EncodeToString(tp)
	}

	return jwk, nil
}

// ParseKey reads a private key from a JWK or a PEM (PKCS#1, SEC1 or PKCS#8).
// Non-empty kid and alg override the values in the key.
func ParseKey(data []byte, kid, alg string) (*jose.JSONWebKey, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("the key is empty")
	}

	var key crypto.PrivateKey
	if data[0] == '{' {
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(data, &jwk); err != nil {
			return nil, fmt.Errorf("invalid JWK: %w", err)
		}
		if jwk.IsPublic() {
			return nil, errors.New("the key must be a private key")
		}
		if kid == "" {
			kid = jwk.KeyID
		}
		if alg == "" {
			alg = jwk.Algorithm
		}
		key = jwk.Key
	} else {
		var err error
		if key, err = parsePEM(data); err != nil {
			return nil, err
		}
	}

	return ParseKeyFromCrypto(key, kid, alg)
}

func parsePEM(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the key is neither a JWK nor a PEM")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block %q; expected a private key", block.Type)
	}
}

func defaultAlgorithm(key crypto.PrivateKey) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return string(jose.RS256), nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return string(jose.ES256), nil
		case elliptic.P384():
			return string(jose.ES384), nil
		case elliptic.P521():
			return string(jose.ES512), nil
		}
		return "", errors.New("unsupported elliptic curve")
	case ed25519.PrivateKey:
		return string(jose.EdDSA), nil
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}
}

// PublicJWKS returns the public half of key as a JWK Set.
func PublicJWKS(key *jose.JSONWebKey) jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.Public()}}
}
