# grafana-editor

An MCP server for editing Grafana, authenticated via Microsoft Entra ID SSO.

It exposes tools for exploring and querying one Grafana instance's
datasources, so that a client can find out what data actually exists before
writing a query or a dashboard panel. Dashboard writing is still to come.

Callers are authenticated as themselves against Entra ID; calls to Grafana
are then made with a single Grafana service account token, so Grafana sees
one identity rather than the signed-in user. Only reads are exposed today,
so that distinction does not yet affect what anyone can do.

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

## How it talks to Grafana

Every Grafana call carries a bearer token read from the file named by
`grafana.service-account-token-path`. Naming the token by path rather than by
value keeps it out of the config file, which is a ConfigMap in the deployed
setup, and lets it come from a mounted Kubernetes secret instead. The file is
re-read whenever its size or mtime changes, so rotating the secret does not
need a restart.

Create the token in Grafana under **Administration → Users and access →
Service accounts**. For the tools exposed today it needs the **Viewer** role,
which carries `datasources:read` and `datasources:query`.

Datasource queries go through Grafana's datasource proxy
(`/api/datasources/proxy/uid/...`), so Grafana's own datasource
authentication and access control still apply and this server never needs
credentials for Mimir or Loki themselves.

Prometheus-shaped datasources (`prometheus`, which is also how Grafana reports
a Mimir or Thanos backend, and `grafana-amazonprometheus-datasource`) and
`loki` are queryable. `list_datasources` reports `queryable: false` for
anything else, and a query against one names the type it got and the types it
needed.

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
- `list_datasources` — the datasources Grafana has, with their uids, types,
  and whether this server can query them.
- `list_metrics` — metric names on a Prometheus-shaped datasource.
- `describe_metrics` — the type, unit and help text a metric was exported
  with, which is what decides whether a panel needs `rate()` and how it
  should be formatted.
- `list_labels` — label names on a Prometheus or Loki datasource.
- `list_label_values` — the values one label takes; this is what fills in a
  dashboard template variable's options.
- `query_instant` — evaluate PromQL or LogQL at a single instant.
- `query_range` — evaluate PromQL or LogQL over a window, which is the shape
  a time series panel draws.

Three conventions run through all of them, so that a caller does not have to
carry Grafana's quirks:

- A datasource is named by **uid or display name**, whichever the caller
  happens to be holding.
- Times are given as an RFC 3339 timestamp, unix seconds, or a relative
  expression (`now`, `now-15m`, `now-6h`). Omitting them queries the last
  hour. The server sends RFC 3339 onwards, which sidesteps Prometheus reading
  a bare number as unix seconds while Loki reads it as nanoseconds.
- A range query with no `step` gets one that yields a couple of hundred
  points over the window, snapped to a value a human would have picked, and
  the reply reports which step was used.

Large results are truncated rather than returned in full, and a truncated
result carries a `truncated` field saying what was dropped and how to ask for
less.

## Test it

```sh
uv run pytest
```

## Build a container image

```sh
docker build -t grafana-editor .
```

The image expects its config at `/config/grafana-editor.toml` by default.
