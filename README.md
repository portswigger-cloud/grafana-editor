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
- `pyjwt` to validate Entra-issued access tokens against the tenant's JWKS
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
4. This server validates that token's signature (via Entra's JWKS),
   issuer, audience and expiry, and reads the caller's email out of it.

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

Fill in the tenant ID, client ID, and this server's own public URL in
`config.toml.example`.

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
