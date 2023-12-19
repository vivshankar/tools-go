package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/golang-jwt/jwt/v4"
)

func Sign(ctx context.Context, privateKey []byte, claims interface{}, header map[string]interface{}) (
	signedJWT string, err error) {

	var key interface{}
	var jwk jose.JSONWebKey
	if e := json.Unmarshal(privateKey, &jwk); e != nil {
		if key, e = jwt.ParseRSAPrivateKeyFromPEM(privateKey); e != nil {
			if key, e = jwt.ParseECPrivateKeyFromPEM(privateKey); e != nil {
				return "", fmt.Errorf("unable to parse the private key")
			}
		}
	} else {
		key = jwk
	}

	return signWithKey(ctx, key, claims, header)
}

func signWithKey(ctx context.Context, key interface{}, claims interface{}, header map[string]interface{}) (
	signedJWT string, err error) {

	if header == nil {
		header = map[string]interface{}{}
	}

	alg, _ := header["alg"].(string)

	switch t := key.(type) {
	case *jose.JSONWebKey:
		header["alg"] = t.Algorithm
		return generateToken(claims, header, jose.SignatureAlgorithm(t.Algorithm), t.Key)
	case jose.JSONWebKey:
		header["alg"] = t.Algorithm
		return generateToken(claims, header, jose.SignatureAlgorithm(t.Algorithm), t.Key)
	case *rsa.PrivateKey:
		if alg == "" {
			alg = string(jose.RS256)
		}

		header["alg"] = alg
		return generateToken(claims, header, jose.SignatureAlgorithm(alg), t)
	case *ecdsa.PrivateKey:
		if alg == "" {
			alg = string(jose.ES256)
		}

		header["alg"] = alg
		return generateToken(claims, header, jose.SignatureAlgorithm(alg), t)
	case jose.OpaqueSigner:
		switch tt := t.Public().Key.(type) {
		case *rsa.PrivateKey:
			if len(t.Algs()) > 0 {
				alg = string(t.Algs()[0])
			}

			if alg == "" {
				alg = string(jose.RS256)
			}

			header["alg"] = alg
			return generateToken(claims, header, jose.SignatureAlgorithm(alg), t)
		case *ecdsa.PrivateKey:
			if len(t.Algs()) > 0 {
				alg = string(t.Algs()[0])
			}

			if alg == "" {
				alg = string(jose.ES256)
			}

			header["alg"] = alg
			return generateToken(claims, header, jose.SignatureAlgorithm(alg), t)
		default:
			return "", fmt.Errorf("unsupported private / public key pairs: %T, %T", t, tt)
		}
	default:
		return "", fmt.Errorf("unsupported private key type: %T", t)
	}
}

func generateToken(claims interface{}, header map[string]interface{}, signingMethod jose.SignatureAlgorithm, privateKey interface{}) (
	rawToken string, err error) {

	if header == nil || claims == nil {
		err = fmt.Errorf("either claims or header is nil")
		return
	}

	var signer jose.Signer
	key := jose.SigningKey{
		Algorithm: signingMethod,
		Key:       privateKey,
	}

	h := map[jose.HeaderKey]interface{}{
		"typ": "JWT",
	}

	for k, v := range header {
		h[jose.HeaderKey(k)] = v
	}

	opts := &jose.SignerOptions{ExtraHeaders: h}
	signer, err = jose.NewSigner(key, opts)
	if err != nil {
		return
	}

	rawToken, err = josejwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return
	}

	return
}
