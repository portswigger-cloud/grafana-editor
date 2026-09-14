# grafana-editor

An MCP server for editing Grafana, authenticated via Microsoft Entra ID SSO.

Grafana-editing tools are still to come. For now this is the authentication
scaffolding plus one tool, `whoami`, that returns the email address of the
signed-in user, so the SSO plumbing can be exercised end to end before any
Grafana-specific tool is built on top of it.

It uses:

- `uv` for project and dependency management
- `mcp` / `MCPServer` for the MCP protocol, using its resource-server-only
  OAuth support
- `starlette` as the ASGI application
- `hypercorn` as the HTTP server
- `pyjwt` to validate access tokens against their issuer's JWKS
- `pytest` for tests

## How authentication works

This server never talks to Entra to log anyone in. Instead:

1. An MCP client (e.g. Claude) fetches
   `{resource-server-url}/.well-known/oauth-protected-resource` from this
   server, which names Entra as the authorization server to use.
2. The client runs the OAuth 2.1 authorization code flow (with PKCE)
   directly against Entra, in the user's browser.
3. Entra issues an access token scoped to this server's App ID URI, which
   the client sends as a `Bearer` token on every MCP request.
4. This server validates that token's signature, issuer, audience and
   expiry against a configured `[[role]]`, and reads the caller's email out
   of it.

Those two halves are configured separately, because they are separate
things:

- `resource-server-url`, `origin` and `scopes` are what step 1 publishes:
  where this server is reachable, which authorization server to
  authenticate against, and which scope to ask it for.
- each `[[role]]` says which tokens step 4 accepts, as an `issuer`/
  `audience` pair. Signing keys are found by reading `jwks_uri` out of
  `{issuer}/.well-known/openid-configuration`, so nothing about the
  provider is hardcoded; a role may set `jwks-uri` itself for an issuer
  that publishes no discovery document. A token is accepted if it matches
  any one role, so a second issuer just means a second `[[role]]`.

An issuer is not the same thing as the authorization server clients talk
to, and for Entra it usually isn't: an app registration whose manifest
leaves `requestedAccessTokenVersion` at its default issues v1 tokens, whose
`iss` is `https://sts.windows.net/{tenant}/`, even though the client
authenticated via the v2 endpoints that `origin` names. Read the `iss`
claim of a token your tenant actually issues rather than assuming — a
rejected token is logged with both the expected and the received value.

That means setting this up requires an **app registration in Entra ID**:

1. Create an app registration. Note its **Application (client) ID** and
   your **Directory (tenant) ID**.
2. Under "Expose an API", accept the default Application ID URI
   (`api://<client-id>`) and add a scope (e.g. `mcp.access`).
3. Under "Token configuration", add `email` as an optional claim on the
   **access token** — the `preferred_username` claim Entra includes by
   default is usually an email address too, but isn't guaranteed to be one.
4. Register the MCP client as an authorized client for that scope (Entra's
   support for OAuth dynamic client registration is limited, so which
   clients this covers depends on how your MCP client obtains credentials —
   check its docs for connecting to an Entra-protected MCP server).

Fill in this server's own public URL, the tenant's v2 endpoint as `origin`,
and the role's `issuer` and `audience` in `config.toml.example`. List the
scope from step 2 in `scopes`, qualified with the Application ID URI
(`api://<client-id>/mcp.access`) — that is the form Entra resolves a scope
against. It is both advertised as `scopes_supported` in this server's OAuth
Protected Resource Metadata and required on every request. Advertising it is
what stops clients falling back to requesting only generic OIDC scopes
(`openid profile email offline_access`), none of which belong to this
resource — which Entra rejects with AADSTS9010010.

### A note on custom Application ID URIs and trailing slashes

If you customise the Application ID URI to an `https://` URL under your own
domain (rather than the default `api://<client-id>`), set the role's
`audience` to exactly that value, and keep `resource-server-url` and the
prefix of each entry in `scopes` the same string too. Entra refuses to register an Application ID URI that ends in a
slash, so the whole set should be slash-free.

Take care not to let a trailing slash creep back in: pydantic's `AnyHttpUrl`
normalises `https://host` to `https://host/`, so `AuthSettings` is handed
plain strings (it sets `url_preserve_empty_path`, keeping the slash-free
form) rather than URLs we built ourselves. A mismatch here shows up as an
`aud` claim that doesn't match `audience` — the rejection log names both
values.

## Run it

```sh
cp config.toml.example config.toml
# edit config.toml with your tenant details
uv run grafana-editor --config config.toml
```

Without Entra configured, for local development only:

```sh
uv run grafana-editor --config config.toml --disable-auth
```

With `--disable-auth`, the `whoami` tool has no signed-in user to report and
returns an error explaining that — it does not fabricate an email address.

Then connect an MCP client or the inspector to:

```text
http://127.0.0.1:8000/mcp
```

## Exposed MCP data

Tools:

- `whoami` — returns `{"email": "..."}` for the signed-in user.

## Test it

```sh
uv run pytest
```

## Build a container image

```sh
docker build -t grafana-editor .
```

The image expects its config at `/config/grafana-editor.toml` by default.
