# tools-go
Tools that are possibly useful for others

## Running

```sh
make run        # serves on http://localhost:8080
make docker-run
```

For OIDC Debugger:

1. `make run`, then open <http://localhost:8080/oidc-debugger>. The first start creates `bin/client.jwk` (see [private_key_jwt](#private_key_jwt)).
2. At the OP, register a client with the redirect URI `http://localhost:8080/oidc/callback` (a public client needs no more). For `private_key_jwt`, also set the client's JWKS URI to `http://localhost:8080/oidc/jwks.json`. The OP must be able to reach that URL, so use a tunnel such as ngrok for a hosted tenant, and open tools through the tunnel URL so the redirect URI matches.
3. Fill in the form and select **Sign in**.

`make docker-build` does not work while `go.mod` has the local `replace` for `verify-auth-go` (see [Development](#development)), because that directory is outside the Docker build context. It works once a release is tagged and the `replace` is removed.

## JWT Studio

`/jwt-studio` inspects, verifies and signs JWTs. Everything runs in the browser except signing, which uses `POST /jwt/sign`.

## OIDC Debugger

`/oidc-debugger` runs an authorization code flow with PKCE against an IBM Verify tenant or any OpenID provider, then shows the token response and the validated tokens. It is meant for learning and testing.

1. Enter the tenant hostname or the OP issuer. A bare hostname such as `acme.verify.ibm.com` becomes `https://acme.verify.ibm.com/oauth2`. A value with a scheme is used as the issuer. The discovery document is cached for an hour.
2. Enter the client ID, scopes and, optionally, `authorization_details` ([RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396)) as a JSON array.
3. Choose the client authentication: a public client, or `private_key_jwt`.
4. Register the **redirect URI** shown on the form on the client at the OP. It is `{scheme}://{host}/oidc/callback`, where the scheme honors `X-Forwarded-Proto`.
5. Select **Sign in**. After you authenticate, the OP redirects to `/oidc/callback`. tools exchanges the code, then shows:
   - the token response,
   - the access token, validated with the SDK (signature, `iss`, `exp` and `iat` for a JWT, or introspection for an opaque token),
   - the ID token, validated with the SDK.

Each sign-in can be used once, and a pending sign-in expires after 10 minutes. The result page has a **Run again** button that repeats the flow against the same OP with the same client, authentication method, redirect URI, scopes, `authorization_details` and any pasted key, using a fresh state and PKCE verifier. It is also offered when the OP returns an error or the code exchange fails, as long as the sign-in was started by this service. **New flow** returns to the form to change anything.

### private_key_jwt

tools signs the client assertion with its own key and publishes the public key at `/oidc/jwks.json`. Register that URL as the client's JWKS URI at the OP. The key has a random UUID `kid`.

The private key is the file `client.jwk` next to the server executable (`bin/client.jwk` for `make run`). It is created on first start if it is missing, and loaded on later starts, so the `kid` stays stable. The Docker build runs `tools-server -generate-key` and bakes the key into the image, so every container from that image shares it. Delete the file to rotate the key. A file that exists but cannot be parsed stops the OIDC tool instead of being overwritten.

All users of the same instance share the key, which is fine for learning and unsuitable for anything real.

You can also paste your own private key on the form (JWK or PEM, with an optional `kid` and `alg`). The OP must already trust its public key, because it is not in the tools JWKS. It is held in memory for up to 10 minutes.

## Development

`go.mod` uses a `replace` directive that points `github.com/ibm-verify/verify-auth-go` at `../../ibm-verify/verify-auth-go`, because the changes this tool needs are not released yet. Remove the directive and update the version once a release includes them.

```sh
go build ./... && go vet ./... && go test ./...
```
