# `mcp-remote`

Connect an MCP Client that only supports local (stdio) servers to a Remote MCP Server, with auth support:

## Why is this necessary?

So far, the majority of MCP servers in the wild are installed locally, using the stdio transport. This has some benefits: both the client and the server can implicitly trust each other as the user has granted them both permission to run. Adding secrets like API keys can be done using environment variables and never leave your machine. And building on `npx` and `uvx` has allowed users to avoid explicit install steps, too.

But there's a reason most software that _could_ be moved to the web _did_ get moved to the web: it's so much easier to find and fix bugs & iterate on new features when you can push updates to all your users with a single deploy.

With the latest MCP [Authorization specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization), we now have a secure way of sharing our MCP servers with the world _without_ running code on user's laptops. Or at least, you would, if all the popular MCP _clients_ supported it yet. Most are stdio-only, and those that _do_ support HTTP+SSE don't yet support the OAuth flows required.

That's where `mcp-remote` comes in. As soon as your chosen MCP client supports remote, authorized servers, you can remove it. Until that time, drop in this one liner and dress for the MCP clients you want!

## Usage

All the most popular MCP clients (Claude Desktop, Cursor & Windsurf) use the following config format:

```json
{
  "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ]
    }
  }
}
```

### Custom Headers

To bypass authentication, or to emit custom headers on all requests to your remote server, pass `--header` CLI arguments:

```json
{
  "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--header",
        "Authorization: Bearer ${AUTH_TOKEN}"
      ],
      "env": {
        "AUTH_TOKEN": "..."
      }
    },
  }
}
```

**Note:** Cursor, Codex-Cli and Claude Desktop (Windows) have a bug where spaces inside `args` aren't escaped when it invokes `npx`, which ends up mangling these values. You can work around it using:

```jsonc
{
  // rest of config...
  "args": [
    "mcp-remote",
    "https://remote.mcp.server/sse",
    "--header",
    "Authorization:${AUTH_HEADER}" // note no spaces around ':'
  ],
  "env": {
    "AUTH_HEADER": "Bearer <auth-token>" // spaces OK in env vars
  }
},
```

To keep a credential out of the process arguments — where any other user on the machine can read it from the process list — put the headers in a file instead and pass `--header-file`. One `Name: value` per line; `#` starts a comment.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--header-file",
        "/path/to/headers.txt"
      ]
```

```
# credentials for the example server
Authorization: Bearer my-token
X-Custom-Header: custom-value
```

A file that cannot be read is an error rather than a warning, so a mistyped path fails immediately instead of sending the request unauthenticated.

### Multiple Instances

To run multiple instances of the same remote server with different configurations (e.g., different Atlassian tenants), use the `--resource` flag to isolate OAuth sessions:

```json
{
  "mcpServers": {
    "atlassian_tenant1": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://mcp.atlassian.com/v1/sse",
        "--resource",
        "https://tenant1.atlassian.net/"
      ]
    },
    "atlassian_tenant2": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://mcp.atlassian.com/v1/sse",
        "--resource",
        "https://tenant2.atlassian.net/"
      ]
    }
  }
}
```

Each unique combination of server URL, resource, custom headers, and `--authorize-param` values will maintain separate OAuth sessions and token storage.

The `--resource` value is sent as the RFC 8707 resource indicator on the authorization, token and
refresh requests alike, so they always agree.

### Extra authorization parameters

Some authorization servers require parameters of their own on the authorize call. Pass each as
`--authorize-param key=value`, repeating the flag as needed:

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/mcp",
        "--authorize-param",
        "access_type=offline",
        "--authorize-param",
        "prompt=consent"
      ]
```

Those two are what Google wants before it will part with a refresh token — it does not recognise the
`offline_access` scope. Auth0 wants `audience=https://your-api` to issue a JWT rather than an opaque
token. `login_hint=user@example.com` is also common.

These apply to the authorization request only. `resource` is the exception: RFC 8707 wants the same
value on the token and refresh requests too, and only `--resource` puts it there. Parameters the flow
derives per request — `state`, `code_challenge`, `client_id`, `redirect_uri`, `response_type` — are
refused, because a value that disagrees with the real one surfaces as an opaque server error.

Changing these starts a new sign-in, since a parameter like `audience` decides which API the token is
for and a token issued for one is not valid for another.

Some authorization servers reject the resource parameter outright — Microsoft Entra ID v2 answers
`AADSTS9010010`, for example. Pass `--disable-resource-parameter` to omit it entirely:

```json
{
  "mcpServers": {
    "entra-example": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/mcp",
        "--disable-resource-parameter"
      ]
    }
  }
}
```

### Flags

* If `npx` is producing errors, consider adding `-y` as the first argument to auto-accept the installation of the `mcp-remote` package.

```json
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ]
```

* To force `npx` to always check for an updated version of `mcp-remote`, add the `@latest` flag:

```json
      "args": [
        "mcp-remote@latest",
        "https://remote.mcp.server/sse"
      ]
```

* To change which port `mcp-remote` listens for an OAuth redirect, add an additional argument after the server URL. By default the port is derived from the server URL, so every server gets a stable port of its own somewhere in `3335`-`49150`, and `mcp-remote` walks up to 8 ports from there if it finds one taken. A port you pass explicitly is used as-is: it implies a `redirect_uri` the authorization server has already been given, so `mcp-remote` fails rather than quietly moving to a different one. `--static-oauth-client-info` pins the port the same way, for the same reason.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "9696"
      ]
```

* To change which host `mcp-remote` registers as the OAuth callback URL (by default `localhost`), add the `--host` flag.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--host",
        "127.0.0.1"
      ]
```

* To change the path `mcp-remote` serves the OAuth callback on (by default `/oauth/callback`), add the `--callback-path` flag. The path must start with `/`, and `/wait-for-auth` is reserved.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--callback-path",
        "/custom/callback"
      ]
```

* To allow HTTP connections in trusted private networks, add the `--allow-http` flag. Note: This should only be used in secure private networks where traffic cannot be intercepted.

```json
      "args": [
        "mcp-remote",
        "http://internal-service.vpc/sse",
        "--allow-http"
      ]
```

* To enable detailed debugging logs, add the `--debug` flag. This will write verbose logs to `~/.mcp-auth/{server_hash}_debug.log` with timestamps and detailed information about the auth process, connections, and token refreshing.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--debug"
      ]
```

* To suppress default logs, add the `--silent` flag. This will prevent logs from being emitted, except in the case where `--debug` is also passed.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--silent"
      ]
```

* To enable an outbound HTTP(S) proxy for mcp-remote, add the `--enable-proxy` flag. When enabled, mcp-remote will use the proxy settings from common environment variables (for example `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`).

```json
    "args": [
      "mcp-remote",
      "https://remote.mcp.server/sse",
      "--enable-proxy"
    ],
    "env": {
      "HTTPS_PROXY": "http://127.0.0.1:3128",
      "NO_PROXY": "localhost,127.0.0.1"
    }
```

* To ignore specific tools from the remote server, add the `--ignore-tool` flag. This will filter out tools matching the specified patterns from both `tools/list` responses and block `tools/call` requests. Supports wildcard patterns with `*`.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--ignore-tool",
        "delete*",
        "--ignore-tool",
        "remove*"
      ]
```

You can specify multiple `--ignore-tool` flags to ignore different patterns. Examples:
- `delete*` - ignores all tools starting with "delete" (e.g., `deleteTask`, `deleteUser`)
- `*account` - ignores all tools ending with "account" (e.g., `getAccount`, `updateAccount`)
- `exactTool` - ignores only the tool named exactly "exactTool"

* To change the timeout for the OAuth callback (by default `30` seconds), add the `--auth-timeout` flag with a value in seconds. This is useful if the authentication process on the server side takes a long time.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--auth-timeout",
        "60"
      ]
```

* To change the network timeouts, add `--connect-timeout`, `--headers-timeout` or `--body-timeout`, each with a value in seconds. These apply to every outbound request, including the OAuth ones.

  * `--connect-timeout` bounds establishing the TCP connection (default `10`). Lower it to fail faster on an unreachable server.
  * `--headers-timeout` bounds waiting for response headers (default `300`).
  * `--body-timeout` bounds a gap between chunks of a response body (default `300`). This is the one that closes an idle SSE stream after five minutes; pass `0` to disable it for servers that push infrequently.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--connect-timeout",
        "30",
        "--body-timeout",
        "0"
      ]
```

* To stop an idle connection being dropped, add the `--keep-alive` flag. The proxy then sends a `ping` every 30 seconds, which is enough traffic to keep a server — or a load balancer in front of one — from reaping a session that has been quiet for a few minutes. Use `--ping-interval` with a value in seconds to change the period; setting it turns keep-alive on, so the two flags are only both needed when you want the default period spelled out.

  This is the opposite end of the problem from `--body-timeout`: that one governs how long *we* wait, whereas this keeps the *other* side from hanging up.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--keep-alive",
        "--ping-interval",
        "60"
      ]
```

* To connect over IPv4 only, add the `--ipv4` flag. Useful when a hostname resolves to both IPv4 and IPv6 addresses but the IPv6 routes silently black-hole rather than being refused — connection attempts then time out instead of failing over, and the request never completes.

```json
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse",
        "--ipv4"
      ]
```

### Transport Strategies

MCP Remote supports different transport strategies when connecting to an MCP server. This allows you to control whether it uses Server-Sent Events (SSE) or HTTP transport, and in what order it tries them.

Specify the transport strategy with the `--transport` flag:

```bash
npx mcp-remote https://example.remote/server --transport sse-only
```

**Available Strategies:**

- `http-first` (default): Tries HTTP transport first, falls back to SSE if HTTP fails with a 404 error
- `sse-first`: Tries SSE transport first, falls back to HTTP if SSE fails with a 405 error
- `http-only`: Only uses HTTP transport, fails if the server doesn't support it
- `sse-only`: Only uses SSE transport, fails if the server doesn't support it

### Protocol Eras (2026-07-28 servers)

The `2026-07-28` revision of MCP retired the `initialize` handshake and the session behind it. A
server that implements it serves stateless requests that each carry their own protocol version and
capabilities, and advertises itself through `server/discover` instead of answering a handshake.

Most desktop hosts still speak the `2025-11-25` era. The specification's compatibility matrix puts
that pair — legacy client, modern server — in the one cell that simply fails, because a legacy client
has no way to fall forward. The fix it names is a *dual-era client*, which is what `mcp-remote`
becomes with `--protocol auto`:

```bash
npx mcp-remote https://example.remote/mcp --protocol auto
```

**Available modes:**

- `legacy` (default): sends the client's `initialize` straight through, exactly as every earlier
  release did. Nothing is probed.
- `auto`: spends one `server/discover` on the first handshake. If a `2026-07-28` server answers,
  `mcp-remote` answers the local client's handshake itself and rewrites every later request into the
  modern era — per-request `_meta`, matching `MCP-Protocol-Version` header. If anything else answers,
  the handshake goes out untouched and nothing changes.

It is off by default because every server in the wild today is a legacy one, and the probe is a round
trip those connections do not need.

The two modern surfaces with no `2025-11-25` equivalent are bridged as well:

- **Change notifications.** The modern era only sends `notifications/tools/list_changed` and friends
  down a `subscriptions/listen` stream the client opens. A 2025-era client never opens one, so
  `mcp-remote` opens it on the client's behalf — asking for exactly the notifications the server said
  it can send — and passes each one on in the shape that era expects.
- **Multi-round-trip requests.** When a server answers with `input_required`, asking for sampling,
  elicitation or roots mid-request, `mcp-remote` unpacks the embedded questions and puts them to the
  client as the ordinary server-initiated requests it already understands, then retries the original
  request with the answers and a byte-exact echo of the server's `requestState`. The client is never
  told any of this happened: it is still waiting on the one request it sent, and that is what it is
  answered with. Capped at 10 rounds.

A question this proxy cannot put to a 2025-era client — anything outside sampling, elicitation and
roots, or a URL-mode elicitation, or one the client never declared it supports — is reported as an
error rather than dropped.

Three methods the modern era retired are honoured by `mcp-remote` itself rather than forwarded to a
server that no longer has them, because the capabilities the client is handed still advertise them:

- `resources/subscribe` / `resources/unsubscribe` become entries on the `subscriptions/listen`
  stream, which is reopened whenever the set changes.
- `logging/setLevel` is recorded and carried as the per-request `io.modelcontextprotocol/logLevel`
  that replaced it — without which a modern server sends no logs at all.

### Static OAuth Client Metadata

MCP Remote supports providing static OAuth client metadata instead of using the mcp-remote defaults.
This is useful when connecting to OAuth servers that expect specific client/software IDs or scopes.

Provide the client metadata as a JSON string or as a `@` prefixed filepath with the `--static-oauth-client-metadata` flag:

```bash
npx mcp-remote https://example.remote/server --static-oauth-client-metadata '{ "scope": "space separated scopes" }'
# uses node readfile, so you probably want to use absolute paths if you're not sure what the cwd is
npx mcp-remote https://example.remote/server --static-oauth-client-metadata '@/Users/username/Library/Application Support/Claude/oauth_client_metadata.json'
```

What you provide is merged over the defaults, so this is also how you pin a value mcp-remote would
otherwise negotiate. `token_endpoint_auth_method` is picked from the authorization server's
`token_endpoint_auth_methods_supported`: `none` when the server accepts public clients, otherwise
`client_secret_post`, otherwise `client_secret_basic`. Override it when the server needs something
else:

```bash
npx mcp-remote https://example.remote/server --static-oauth-client-metadata '{ "token_endpoint_auth_method": "client_secret_post" }'
```

### Static OAuth Client Information

Per the [spec](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization#2-4-dynamic-client-registration),
servers are encouraged but not required to support [OAuth dynamic client registration](https://datatracker.ietf.org/doc/html/rfc7591).

For these servers, MCP Remote supports providing static OAuth client information instead.
This is useful when connecting to OAuth servers that require pre-registered clients.

Provide the client metadata as a JSON string or as a `@` prefixed filepath with the `--static-oauth-client-info` flag:

```bash
export MCP_REMOTE_CLIENT_ID=xxx
export MCP_REMOTE_CLIENT_SECRET=yyy
npx mcp-remote https://example.remote/server --static-oauth-client-info "{ \"client_id\": \"$MCP_REMOTE_CLIENT_ID\", \"client_secret\": \"$MCP_REMOTE_CLIENT_SECRET\" }"
# uses node readfile, so you probably want to use absolute paths if you're not sure what the cwd is
npx mcp-remote https://example.remote/server --static-oauth-client-info '@/Users/username/Library/Application Support/Claude/oauth_client_info.json'
```

### Client ID Metadata Documents

[SEP-991](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) lets an
authorization server accept an HTTPS URL as the `client_id`, where that URL serves a JSON document
describing the client. Servers that support it advertise
`"client_id_metadata_document_supported": true` in their authorization server metadata, and no
dynamic registration is needed.

Point mcp-remote at your document with `--client-metadata-url`:

```bash
npx mcp-remote https://example.remote/server --client-metadata-url https://client.example.com/.well-known/oauth-client-metadata
```

The URL must use HTTPS and have a path — a bare origin is rejected. If the server does not advertise
support, mcp-remote registers dynamically as usual, so the flag is safe to leave in place.

The document you host has to list the `redirect_uri` mcp-remote will send, which contains the OAuth
callback port. Passing this flag makes that port strict: mcp-remote uses the port derived from the
server URL (or the one you pass explicitly) and fails rather than quietly moving to another one, so
the `redirect_uris` in your document stay correct. Run once to see the port it picked, or choose it
yourself:

```bash
npx mcp-remote https://example.remote/server 3334 --client-metadata-url https://client.example.com/.well-known/oauth-client-metadata
```

### Signing In Without a User

Some servers are not protected on behalf of a person at all — an internal MCP server reached by a
scheduled job, say, where there is no user to consent and no browser to consent in. For those,
`--client-credentials` uses the
[OAuth Client Credentials grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4): the
client presents its own credentials and is issued a token for itself.

```bash
npx mcp-remote https://example.remote/mcp \
  --client-credentials \
  --static-oauth-client-info '{"client_id":"my-client","client_secret":"${MCP_CLIENT_SECRET}"}'
```

The credentials come from `--static-oauth-client-info`, which accepts inline JSON or `@path/to/file.json`.
**`${ENV_VAR}` placeholders are expanded from the environment** in both forms, so the secret need not sit
in a command line where every other process on the machine can read it. Nothing logs the expanded value.

The token endpoint, the scope and the RFC 8707 `resource` indicator are discovered and applied the same
way as for every other flow, and `client_secret_basic` or `client_secret_post` is chosen from what the
authorization server advertises. No refresh token is involved: the credentials are the durable thing, so
an expired token is replaced by asking for another the same way the first was obtained.

If an internal server does not publish RFC 9728 or RFC 8414/OIDC discovery metadata, provide its known
token endpoint explicitly. This skips discovery and is accepted only with `--client-credentials`:

```bash
npx mcp-remote https://example.remote/mcp \
  --client-credentials \
  --token-endpoint https://auth.example.com/oauth/token \
  --static-oauth-client-info '{"client_id":"my-client","client_secret":"${MCP_CLIENT_SECRET}"}' \
  --static-oauth-client-metadata '{"scope":"mcp.read mcp.write","token_endpoint_auth_method":"client_secret_basic"}'
```

The explicit endpoint must use HTTPS, except for an HTTP loopback endpoint. Credentials and URL
fragments are refused in the endpoint URL, and changing the endpoint selects a separate token cache.
Discovery is also skipped on cold startup and 401 retries. Tokens are renewed before expiry using
the same client credentials. With an explicit endpoint, scope and resource are omitted unless
configured; use `--static-oauth-client-metadata` for scope and `--resource` for resource.

### Signing In Without a Browser

The default flow needs a browser on this machine and a loopback port to redirect back to — which a
cron job, an SSH session or a container does not have. If your authorization server supports the
[OAuth Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628), `--device-code`
moves the browser to whatever machine you are actually sitting at:

```bash
npx mcp-remote https://example.remote/server --device-code
```

mcp-remote prints a short code and a URL, then polls until you approve it:

```
To authorize this client, visit:
  https://auth.example.com/activate

And enter the code: WDJB-MJHT

Waiting for approval...
```

The output goes to stderr, which MCP clients capture into their own logs — so in a headless run,
that log is where you read the code. This only has to happen once: the refresh token that comes back
is stored like any other, and later runs are non-interactive.

No callback server is started and no port is bound, so this is also the flow to use when the
loopback port is unavailable.

The server has to advertise `device_authorization_endpoint` in its authorization server metadata;
mcp-remote fails with a clear message rather than falling back to a browser that isn't there. Note
that servers offering this grant often expect a pre-registered client — pair it with
`--static-oauth-client-info` if dynamic registration is refused.

### Load Balancer Session Stickiness

MCP sessions live on one backend, so a server behind a load balancer needs every request from a
client to reach the same node. AWS ALB, Azure Load Balancer and others do this with a cookie the
client is expected to send back.

mcp-remote keeps cookies the MCP server sets and replays them on later requests, including from the
SSE stream onto the POSTs that follow it. Nothing to configure. Cookies are held in memory for the
life of the process, never written to disk, and only ever sent back to the exact origin that set
them — `Domain` is ignored, so nothing travels to another host.

A `Cookie` you pass yourself with `--header` always wins.

To turn it off:

```bash
npx mcp-remote https://example.remote/server --disable-cookies
```

### Using the ID Token as the Bearer Credential

By default mcp-remote sends the OAuth **access token**, which says what the caller is allowed to
do. Some servers instead verify **who** the caller is: they validate an OIDC **ID token** against a
JWKS endpoint and read identity claims such as `sub` and `email` from it. AWS Cognito in front of
Bedrock AgentCore works this way, and rejects the access token outright.

Pass `--use-id-token` to send the ID token instead:

```bash
npx mcp-remote https://example.remote/server --use-id-token
```

Only the credential presented to the MCP server changes — the refresh token and the renewal flow
are untouched. Renewal follows the ID token's own `exp` claim rather than the access token's
lifetime, since the ID token is what actually goes on the wire.

An ID token is only issued when `openid` is among the requested scopes. If your server does not
advertise it, ask for it explicitly:

```bash
npx mcp-remote https://example.remote/server --use-id-token --static-oauth-client-metadata '{ "scope": "openid email" }'
```

### Claude Desktop

[Official Docs](https://modelcontextprotocol.io/quickstart/user)

In order to add an MCP server to Claude Desktop you need to edit the configuration file located at:

* macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
* Windows: `%APPDATA%\Claude\claude_desktop_config.json`

If it does not exist yet, [you may need to enable it under Settings > Developer](https://modelcontextprotocol.io/quickstart/user#2-add-the-filesystem-mcp-server).

Restart Claude Desktop to pick up the changes in the configuration file.
Upon restarting, you should see a hammer icon in the bottom right corner
of the input box.

### Cursor

[Official Docs](https://docs.cursor.com/context/model-context-protocol). The configuration file is located at `~/.cursor/mcp.json`.

As of version `0.48.0`, Cursor supports unauthed SSE servers directly. If your MCP server is using the official MCP OAuth authorization protocol, you still need to add a **"command"** server and call `mcp-remote`.

### Windsurf

[Official Docs](https://docs.codeium.com/windsurf/mcp). The configuration file is located at `~/.codeium/windsurf/mcp_config.json`.

## Building Remote MCP Servers

For instructions on building & deploying remote MCP servers, including acting as a valid OAuth client, see the following resources:

* https://developers.cloudflare.com/agents/guides/remote-mcp-server/

In particular, see:

* https://github.com/cloudflare/workers-oauth-provider for defining an MCP-comlpiant OAuth server in Cloudflare Workers
* https://github.com/cloudflare/agents/tree/main/examples/mcp for defining an `McpAgent` using the [`agents`](https://npmjs.com/package/agents) framework.

For more information about testing these servers, see also:

* https://developers.cloudflare.com/agents/guides/test-remote-mcp-server/

Know of more resources you'd like to share? Please add them to this Readme and send a PR!

## Troubleshooting

### Clear your `~/.mcp-auth` directory

`mcp-remote` stores all the credential information inside `~/.mcp-auth` (or wherever your `MCP_REMOTE_CONFIG_DIR` points to). If you're having persistent issues, try running:

```sh
rm -rf ~/.mcp-auth
```

Then restarting your MCP client.

Credentials are stored under `mcp-remote-v1`, which names the layout of the store rather than the
version of the package, so upgrading `mcp-remote` no longer signs you out. Releases before this
change kept a separate directory per version — if you have `~/.mcp-auth/mcp-remote-0.x.y`
directories left over, they hold old tokens and can be deleted.

### Check your Node version

Make sure that the version of Node you have installed is [18 or
higher](https://modelcontextprotocol.io/quickstart/server). Claude
Desktop will use your system version of Node, even if you have a newer
version installed elsewhere.

### Restart Claude

When modifying `claude_desktop_config.json` it can helpful to completely restart Claude

### VPN Certs

You may run into issues if you are behind a VPN, you can try setting the `NODE_EXTRA_CA_CERTS`
environment variable to point to the CA certificate file. If using `claude_desktop_config.json`,
this might look like:

```json
{
 "mcpServers": {
    "remote-example": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ],
      "env": {
        "NODE_EXTRA_CA_CERTS": "{your CA certificate file path}.pem"
      }
    }
  }
}
```

### Check the logs

* [Follow Claude Desktop logs in real-time](https://modelcontextprotocol.io/docs/tools/debugging#debugging-in-claude-desktop)
* MacOS / Linux:<br/>`tail -n 20 -F ~/Library/Logs/Claude/mcp*.log`
* For bash on WSL:<br/>`tail -n 20 -f "C:\Users\YourUsername\AppData\Local\Claude\Logs\mcp.log"`
* Powershell: <br/>`Get-Content "C:\Users\YourUsername\AppData\Local\Claude\Logs\mcp.log" -Wait -Tail 20`

## Debugging

### Debug Logs

For troubleshooting complex issues, especially with token refreshing or authentication problems, use the `--debug` flag:

```json
"args": [
  "mcp-remote",
  "https://remote.mcp.server/sse",
  "--debug"
]
```

This creates detailed logs in `~/.mcp-auth/{server_hash}_debug.log` with timestamps and complete information about every step of the connection and authentication process. When you find issues with token refreshing, laptop sleep/resume issues, or auth problems, provide these logs when seeking support.

### Authentication Errors

If you encounter the following error, returned by the `/callback` URL:

```
Authentication Error
Token exchange failed: HTTP 400
```

You can run `rm -rf ~/.mcp-auth` to clear any locally stored state and tokens.

### "Client" mode

Run the following on the command line (not from an MCP server):

```shell
npx -p mcp-remote@latest mcp-remote-client https://remote.mcp.server/sse
```

This will run through the entire authorization flow and attempt to list the tools & resources at the remote URL. Try this after running `rm -rf ~/.mcp-auth` to see if stale credentials are your problem, otherwise hopefully the issue will be more obvious in these logs than those in your MCP client.

## Acknowledgments

[Glen Maddern](https://github.com/geelen) is the original author of `mcp-remote`. He built `mcp-remote` into one of the most popular building blocks in the MCP ecosystem.
