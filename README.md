# valetkey

Every Tool. Your Rules.

valetkey is a self-hosted MCP server that lets AI agents do operations work (open and merge pull requests, trigger deploys, wait for builds, read logs and metrics) inside limits you set. The name comes from a car's valet key: it starts the engine but does not open the trunk.

A token does not only name the tools an agent may call. It names the resources those tools may reach: this repository, these Jenkins jobs, that log stream. Write tools refuse to act on stale state and hand back something to wait on. Each token has a write limit per hour and an optional dry run, and every call to a tool on the token's list is logged, refused ones included.

valetkey is not a general MCP gateway. It can put the remote MCP servers each person adds behind the same front door (see [Your own MCP servers](#your-own-mcp-servers)), but those tools get no resource scope. If you want a gateway with policy for many MCP servers, [Obot](https://github.com/obot-platform/obot), [Bifrost](https://github.com/maximhq/bifrost) and [IBM ContextForge](https://github.com/IBM/mcp-context-forge) do that. Choose valetkey when your concern is what an agent can reach and change in Jenkins, Argo CD, Loki, Prometheus, Bitbucket Cloud and Notion, and you want that written down per token.

## Quickstart

You need an OIDC client from your identity provider (see [Sign-in setup](#sign-in-setup)) with the redirect URI `https://valetkey.example.com/oauth/oidc/callback`, replacing the host with your own.

```sh
touch .env && chmod 600 .env
grep -q '^VAULT_KEY=' .env || printf 'VAULT_KEY=%s\nSESSION_KEY=%s\n' "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" >> .env

docker run -d --name valetkey -p 8080:8080 -v valetkey:/data --env-file .env \
  -e PUBLIC_URL=https://valetkey.example.com \
  -e OIDC_ISSUER=https://accounts.google.com \
  -e OIDC_CLIENT_ID=your-client-id \
  -e OIDC_CLIENT_SECRET=your-client-secret \
  -e ALLOWED_DOMAINS=example.com \
  ghcr.io/rahmadafandi/valetkey
```

Keep `.env`. It holds `VAULT_KEY` and `SESSION_KEY`, and if you lose `VAULT_KEY`, every stored upstream credential becomes unreadable. Generating the keys inline with `-e VAULT_KEY=$(openssl rand -hex 32)` would make a new key each time you recreate the container, which is why they go into a file. You can move the other variables into the same file too, starting from [.env.example](.env.example).

`PUBLIC_URL` is the address people and agents use to reach the server, with no path and no trailing slash. Put TLS in front of it with your usual reverse proxy.

Open `PUBLIC_URL` and sign in. Then add valetkey to an MCP client:

```sh
claude mcp add --transport http valetkey https://valetkey.example.com/mcp
```

The client opens a browser window for you to sign in and approve it. For a bot that cannot do that, create a personal access token instead (see [Personal access tokens](#personal-access-tokens)).

Postgres instead of SQLite: [compose.yaml](compose.yaml) starts valetkey with a Postgres container. Run `docker compose up -d` next to a `.env` file.

Without Docker: `go install github.com/rahmadafandi/valetkey/cmd/valetkey@latest` builds the binary with Go 1.26 or newer, no cgo needed. Set the same variables and run `valetkey`.

## Sign-in setup

valetkey signs people in through any OpenID Connect provider that publishes a discovery document. In every case:

- The redirect URI is `<PUBLIC_URL>/oauth/oidc/callback`.
- Set `ALLOWED_DOMAINS`, `ALLOWED_EMAILS`, or both. The server does not start without one of them, so an instance cannot be open to every account at your provider.
- valetkey asks for the scopes `openid email`.

| Provider | `OIDC_ISSUER` | Notes |
|---|---|---|
| Google | `https://accounts.google.com` | Create an OAuth client of type Web application in Google Cloud. For `ALLOWED_DOMAINS`, valetkey also requires the `hd` claim to match the email's domain, so a personal Google account with a company address is refused. |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | Register an app, add the redirect URI as a Web platform, and create a client secret. Entra does not send `email_verified`, so set `OIDC_TRUST_UNVERIFIED_EMAIL=true`. Check that the ID token carries an `email` claim, and add the `email` optional claim to the app registration if it does not. |
| Keycloak | `https://keycloak.example.com/realms/<realm>` | Create an OpenID Connect client with client authentication on and the redirect URI above. |

The issuer must match the `issuer` field of the provider's discovery document exactly. If it does not, or the document cannot be fetched, the server stops at start and says why.

## Connecting upstreams

An upstream is on when its `<SYSTEM>_URL` is set. Each person then connects their own account on the server's `/connect/<system>` page, and valetkey acts with that person's credentials. The connect page explains where to find each token.

| System | Variable | Value |
|---|---|---|
| Jenkins | `JENKINS_URL` | Base URL, for example `https://jenkins.example.com` |
| Argo CD | `ARGOCD_URL` | Base URL, for example `https://argocd.example.com` |
| Bitbucket Cloud | `BITBUCKET_URL` | API root, `https://api.bitbucket.org/2.0` |
| Loki | `LOKI_URL` | API base URL, see below |
| Metrics | `METRICS_URL` | API base URL, see below |
| Notion | `NOTION_URL` | API root, `https://api.notion.com/v1` |

**Notion.** Each person pastes a Notion personal access token, made at [notion.so/developers/tokens](https://www.notion.so/developers/tokens). It acts as that person and reaches every page they can open. Whether members may create one depends on the plan: on Free and by default on Business, only workspace owners can; on Plus everyone can; admins can widen it on Business and Enterprise. A token reaches one workspace, so the connect page takes up to three, one per workspace. Search looks in each and labels every result with its workspace; the other tools take an ID and use whichever token can open it. The tools search, read pages as markdown, query databases, create pages and add content to the end of a page. Nothing deletes, moves or edits existing content.

Add `<SYSTEM>_INSECURE=true` to skip TLS verification for an endpoint with a self-signed certificate, for example `JENKINS_INSECURE=true`.

**Loki.** `LOKI_URL` is the base of the Loki HTTP API. Use one of:

- Loki directly, or a gateway in front of it: `https://loki.example.com`.
- A Grafana datasource proxy: `https://grafana.example.com/api/datasources/proxy/uid/<uid>`. To find the uid, open Grafana, go to Connections, then Data sources, and open your Loki data source. The address bar ends with `/connections/datasources/edit/<uid>`.

**Metrics.** `METRICS_URL` takes the same two forms. Directly, it accepts any Prometheus-compatible API: Prometheus, Mimir, Thanos or VictoriaMetrics, for example `https://prometheus.example.com`. Through Grafana, use the proxy address of your Prometheus data source, found the same way as for Loki.

Limit in v0.1: multi-tenant Loki that needs an `X-Scope-OrgID` header is not supported yet. valetkey has no setting to send that header.

## Your own MCP servers

Each person can put remote MCP servers of their own behind valetkey, next to the built-in tools. An agent then needs one connection to valetkey instead of one per server, and a token can list the proxied tools like any other. Open **Servers** (`/upstreams`) to add one.

Add a server with a name, its URL and a login kind:

- **Token.** A header name (`Authorization` by default) and its value. valetkey stores the value only after it has fetched the server's tools with it.
- **OAuth.** valetkey signs in to the server the way an MCP client does. It finds the server's authorization server from the `WWW-Authenticate` header of the 401 answer, or from the well-known address, and it needs `S256` in `code_challenge_methods_supported`, so it refuses a server without it. If the server offers dynamic client registration, valetkey registers itself. If not, the page asks for a client ID, and a secret if the client has one, and names the token endpoint's host, the only place the secret is sent. valetkey uses PKCE and sends `resource` with the authorization, token and refresh requests. It requests no `scope` yet, so a server that insists on scopes may not work. To sign in again, use **Sign in again** on the server's page: the old login keeps working until the new one finishes.
- **None.** For a server that needs no login.

The name starts with a lowercase letter or digit, followed by up to 23 lowercase letters, digits or hyphens. Agents see each tool as `<server>__<tool>`, so a tool `search` on a server named `docs` appears as `docs__search`.

### Approving tools

valetkey fetches the server's tool list and shows every tool with its full description and input schema. Nothing reaches an agent until you press **Approve these tools**, and approving stores exactly the list you were shown. The server writes those descriptions and agents follow them, so read them first.

Servers change. **Check for changes** (on the server's page, or **Review tools** when nothing is approved yet) fetches the list again and shows what is new, changed or removed. Until you approve, your agents keep the list you approved before, with one exception: when a review finds that the server no longer lists a tool, valetkey drops that tool right away, since a call to it would fail.

valetkey keeps at most 200 tools per server, and you can add at most 20 servers. A tool is skipped, and listed on the review page, when its input schema is not a JSON object schema or when its prefixed name is not 1 to 64 letters, digits, `_` or `-`. Tools that the MCP SDK drops for an invalid `x-mcp-header` annotation never appear.

### What a token can limit

A token lists proxied tools by name, in their own group on the token form. A token without a tool cannot see or call it. A proxied tool counts as one that changes things when the server sets `destructiveHint: true` or does not set `readOnlyHint: true`. So the write limit and dry run apply to proxied tools. There is no scope for them: valetkey cannot know what the arguments of a tool you added mean, so it cannot limit which resources they reach.

Token grants are by name. If you remove a server and add another with the same name, a token that listed `name__tool` applies to the new server's tool of that name. Check your tokens after you replace a server.

### Reaching internal servers

valetkey calls a server only over https and refuses addresses that are not on the public internet: loopback, private ranges, link-local (including cloud metadata), and similar. `UPSTREAM_ALLOW_HOSTS` is a list of exact host names that skip that check and may use plain http, for an MCP server on your own network:

```sh
UPSTREAM_ALLOW_HOSTS=mcp.internal.example.com,tools.corp.example.com
```

An allowed name trusts whatever its DNS returns, private addresses included, and is reachable on any port. List only names you control. On an IPv6-only network with NAT64, a server that only has an IPv4 address cannot be reached, because `64:ff9b::/96` is refused. [SECURITY.md](SECURITY.md) has the full list.

### Not proxied

stdio servers, resources, prompts, sampling, elicitation and roots. valetkey declares no client capabilities, so a server cannot ask it for them. It sends `User-Agent: valetkey/<version>` on every request to a server. OAuth token refresh is coordinated within one valetkey process, so running several replicas is not supported for this.

## Personal access tokens

OAuth sign-in suits a person at a keyboard, and an OAuth session is not scoped. For an agent or a bot, create a personal access token on `/tokens`. Tokens start with `vk_` and are shown once. Send one as `Authorization: Bearer vk_...` to `<PUBLIC_URL>/mcp`.

The form asks for:

- **Tools.** The tools the token may see and call. Tools that change things are marked.
- **Scope.** A JSON object that says what each tool family may reach. A family you leave out reaches nothing, and a call to it is refused.
- **Expiry.** 7, 30 or 90 days, or never.
- **Write limit per hour.** How many calls that change things the token may make in an hour. The default is 20. Use 0 for no limit.
- **Dry run.** Tools that change things report what they would do and never contact the upstream.

**Edit** on `/tokens` changes all of these but the expiry. The token's value stays, and the change applies from its next call, so narrowing a scope or dropping a tool takes effect without handing the bot a new token.

### Scope keys

| Key | Value | Example | A call is refused when |
|---|---|---|---|
| `bitbucket` | One repository, `workspace/slug`, or a list | `"bitbucket": ["acme/web", "acme/api"]` | the `repo` argument is not listed |
| `jenkins` | A job path, or a list of them | `"jenkins": ["deploy-web", "folder/deploy-api"]` | the job in `jobURL` is not in the list |
| `loki` | One stream selector, or a list | `"loki": ["{app=\"web\"}", "{app=\"api\"}"]` | a stream selector in the query is not listed, or the query has none |
| `argocd` | An app name, or a list of them | `"argocd": ["web", "api"]` | the `app` argument is not in the list |
| `notion` | A page or database ID or link, or a list of them | `"notion": ["https://www.notion.so/acme/Runbooks-1a2b..."]` | the page or database is neither listed nor inside a listed one, which valetkey asks Notion by walking up to 12 parents; search hides results outside it. In dry run a write is not checked, since nothing is sent |
| `metrics` | One set of `label="value"` matchers | `"metrics": "{namespace=\"web\"}"` | any series selector in the query lacks one of the matchers, including a bare `sum(up)`, or the query cannot be parsed |

A whole scope for a token that deploys one service looks like this:

```json
{
  "bitbucket": "acme/web",
  "jenkins": ["deploy-web"],
  "argocd": "web",
  "loki": "{app=\"web\"}",
  "metrics": "{namespace=\"web\"}"
}
```

A key must belong to an upstream you have turned on, and a mistyped key is refused when you create the token. If you later turn that upstream off, the token stops working: `/mcp` answers 401 and the server log names the token id.

### Write limit and dry run

The write limit counts a token's calls to tools that change things (`bitbucket_pr_create`, `bitbucket_pr_merge`, `bitbucket_pr_comment`, `jenkins_deploy`, `jenkins_rebuild`, `argocd_sync`, `notion_page_create`, `notion_page_append`) over the last hour. Calls that ended in `ok`, `error` or `dry_run` count. When the limit is reached, the next write is refused until older calls fall out of the hour. One token's limited writes run one at a time, from the count until the call is recorded, so parallel calls cannot overshoot the limit. A write waits while an earlier write on the same token is still running. The limit holds within one valetkey process; running several replicas against one database would let each replica count on its own. OAuth sessions have no write limit.

A dry-run token goes through the scope and limit checks, then answers `dry-run: would call <tool> with <args>` without contacting the upstream. Read tools run as usual.

### Refusals

A refused call comes back as a tool result marked as an error, not as a protocol error, so the agent can read it and change course:

```
refused: jenkins_deploy: job "deploy-api" is outside this token's scope; it allows deploy-web
refused: bitbucket_pr_merge: write limit of 20/hour reached for this token
```

These refusals are also recorded in the audit log. A call to a tool that is not on the token's list is different: the MCP server that token sees does not list the tool, so the client gets a protocol error, the call never reaches valetkey's tool handler, and it is not in the audit log.

## Activity log and retention

Every call that reaches a tool handler is recorded: refused calls, dry runs and upstream errors as well as successes. `/activity` lists the newest 200 calls with time, token, tool, outcome, message and arguments. Filter by token name, tool or outcome in the page. People see their own calls. Emails in `ADMIN_EMAILS` see everyone's and can also filter by the user's email. `/tokens` shows when each token was last used.

Arguments are stored cut to 4 KiB and messages to 1 KiB. Credentials are not tool arguments, so they do not reach the log. Jenkins build parameters are tool arguments, so they are stored as sent: do not pass secrets as build parameters.

`AUDIT_RETENTION_DAYS` sets how long rows are kept, 90 by default. A cleanup runs every ten minutes. Use 0 to keep rows forever.

## Operations

valetkey runs its database migrations at start. `valetkey migrate status` prints which migrations are applied and which are pending. With the Docker image: `docker exec valetkey /valetkey migrate status`.

valetkey takes a migration lock on every start. If the process dies in the middle of a migration, a row can stay in the `bun_migration_locks` table and block the next start. To recover, stop valetkey and delete the rows: `DELETE FROM bun_migration_locks;`. On Postgres, run that with `psql`. On SQLite, run it with `sqlite3` against `valetkey.db` from the host or another container, since the image has no `sqlite3`, for example `docker run --rm -it -v valetkey:/data alpine sh -c 'apk add --no-cache sqlite && sqlite3 /data/valetkey.db "DELETE FROM bun_migration_locks;"'`. Then start valetkey again.

## Configuration

Names and defaults match [.env.example](.env.example).

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `PUBLIC_URL` | yes | | Public origin of the server, no path and no trailing slash |
| `OIDC_ISSUER` | yes | | OIDC issuer URL; https is required except on localhost, 127.0.0.1 or ::1 |
| `OIDC_CLIENT_ID` | yes | | OIDC client ID |
| `OIDC_CLIENT_SECRET` | yes | | OIDC client secret |
| `ALLOWED_DOMAINS` | one of the two | | Email domains allowed to sign in, comma-separated |
| `ALLOWED_EMAILS` | one of the two | | Exact emails allowed to sign in, comma-separated |
| `OIDC_TRUST_UNVERIFIED_EMAIL` | no | `false` | `true` accepts ID tokens without `email_verified` |
| `ADMIN_EMAILS` | no | | Emails that may see every user's activity |
| `AUDIT_RETENTION_DAYS` | no | `90` | Days to keep the audit log, 0 keeps it forever |
| `VAULT_KEY` | yes | | 64 hex characters or base64 of 32 bytes, seals stored credentials |
| `SESSION_KEY` | yes | | At least 32 characters, signs login sessions |
| `ADDR` | no | `:8080` | Listen address |
| `DATABASE_URL` | no | `sqlite://./valetkey.db` | `sqlite://` path or `postgres://` URL. The image sets `sqlite:///data/valetkey.db` |
| `ACCESS_TOKEN_TTL` | no | `1h` | Lifetime of an OAuth access token |
| `REFRESH_TOKEN_TTL` | no | `720h` | Lifetime of an OAuth refresh token |
| `SESSION_TTL` | no | `12h` | How long a sign-in to the web pages lasts |
| `CATALOG_FILE` | no | `catalog.json` | JSON list of other MCP servers shown on the home page |
| `TZ` | no | `UTC` in the image | Zone for query times written without an offset |
| `JENKINS_URL`, `JENKINS_INSECURE` | no | | Turns Jenkins on, `true` skips TLS verification |
| `ARGOCD_URL`, `ARGOCD_INSECURE` | no | | Turns Argo CD on, `true` skips TLS verification |
| `LOKI_URL`, `LOKI_INSECURE` | no | | Turns Loki on, `true` skips TLS verification |
| `METRICS_URL`, `METRICS_INSECURE` | no | | Turns metrics on, `true` skips TLS verification |
| `BITBUCKET_URL`, `BITBUCKET_INSECURE` | no | | Turns Bitbucket on, `true` skips TLS verification |
| `NOTION_URL`, `NOTION_INSECURE` | no | | Turns Notion on, `true` skips TLS verification |
| `UPSTREAM_ALLOW_HOSTS` | no | | Exact host names of MCP servers that may use http and skip the address check, comma-separated |

## More

- [SECURITY.md](SECURITY.md): how to report a problem, and what valetkey does and does not protect against.
- [CONTRIBUTING.md](CONTRIBUTING.md): running the tests and adding an integration.
- [LICENSE](LICENSE): Apache License 2.0.
