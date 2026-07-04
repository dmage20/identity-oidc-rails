# identity-oidc-rails

An example [OpenID Connect](https://developers.login.gov/oidc/) relying party
for testing and integrating against the [Login.gov](https://login.gov) IdP.
This is a Rails 8 rewrite of
[identity-oidc-sinatra](https://github.com/18F/identity-oidc-sinatra) with the
same routes, environment-variable contract, and behavior, plus a hardened
security baseline (enforced CSP, CSRF protection, secure session cookies,
rate limiting, TLS verification on outbound requests).

- Ruby 4.0.5, Rails 8.1.3
- Stateless: no database; cookie sessions only
- USWDS 3.x frontend served from `public/vendor`

## Running locally

Requires Ruby 4.0.5 (see `.ruby-version`) and Node 22+.

```bash
make setup   # copies .env.example to .env, installs gems + npm deps, vendors USWDS
make run     # boots on http://localhost:9292
```

The default `.env` points at a local IdP at `http://localhost:3000`
([identity-idp](https://github.com/18F/identity-idp)). To target the Login.gov
sandbox instead, remove `idp_url` (it defaults to
`https://idp.int.identitysandbox.gov`).

## Tests and checks

```bash
make test    # rspec + node --test (Web Component)
make lint    # rubocop, brakeman, bundler-audit, npm audit
make check   # lint + test
```

## Configuration

All configuration is via environment variables (dotenv in development), with
names identical to identity-oidc-sinatra:

| Variable | Default | Purpose |
|----------|---------|---------|
| `idp_url` | derived from `idp_environment`/`idp_domain` | IdP base URL |
| `idp_environment` | `int` | Used to derive `idp_url` when unset |
| `idp_domain` | `identitysandbox.gov` | Used to derive `idp_url` when unset |
| `client_id` | `urn:gov:gsa:openidconnect:sp:sinatra` | OIDC client id (private_key_jwt) |
| `client_id_pkce` | `urn:gov:gsa:openidconnect:sp:sinatra_pkce` | OIDC client id (PKCE) |
| `redirect_uri` | `http://localhost:9292/` | Base for the OAuth callback |
| `sp_private_key_path` | `./config/demo_sp.key` | SP key path, or `aws-secretsmanager:<secret-id>` |
| `sp_private_key` | — | Raw SP key (overrides the path) |
| `PKCE` | `false` | Use PKCE instead of private_key_jwt |
| `semantic_ial_values_enabled` | `false` | Use `urn:acr.login.gov` ACR URIs |
| `eipp_allowed` | `false` | Offer Enhanced In-Person Proofing |
| `cache_oidc_config` | `true` | Cache the discovery document |
| `redact_ssn` | `true` | Mask SSN digits in the userinfo display |
| `attempts_shared_secret` | — | Bearer secret for the Attempts API |
| `allow_all_events_plaintext` | `false` | Show attempt events without redaction |
| `signed_events` | `false` | Verify ES256 signatures on attempt events |
| `SECRET_KEY_BASE` | — | Required in production (no Rails credentials file) |
| `NEW_RELIC_LICENSE_KEY` / `NEW_RELIC_APP_NAME` | — | Enable New Relic |

`config/demo_sp.key` is a published demo credential for sandbox testing and is
intentionally committed.

## Endpoints

| Route | Purpose |
|-------|---------|
| `GET /` | Home; sign-in form with IAL/AAL/scope options, or userinfo when logged in |
| `GET /auth/request` | Builds the authorization request and redirects to the IdP |
| `GET /auth/result` | OAuth callback: token exchange, ID-token validation, userinfo |
| `POST /handle-logout` | Clears the session, redirects to RP-initiated logout |
| `GET /logout` | Post-logout landing (from the IdP) |
| `GET /failure_to_proof` | Identity-proofing failure page |
| `GET /api/health` | JSON health check with SP key fingerprint |
| `GET /attempts-api` | SSF Attempts API event viewer (JWE-decrypted, PII-redacted) |
| `POST /ack-events` | Acknowledge (delete) attempt events by jti |
| `GET /up` | Rails liveness check |

## Deployment

Deployed to cloud.gov via GitLab CI (`.gitlab-ci.yml`): merge requests run
`make check`; the `main` branch deploys to the `prod`, `staging`, `int`,
`dev`, and `dm` spaces with the Ruby buildpack. `rake login:deploy_json`
writes build metadata to `public/api/deploy.json`.

A production Docker image is also available:

```bash
docker build -t identity_oidc_rails .
docker run -p 9292:9292 -e SECRET_KEY_BASE=$(openssl rand -hex 64) identity_oidc_rails
```
