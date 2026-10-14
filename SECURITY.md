# Security

## Reporting

Please report a vulnerability through a private security advisory on this repository: open the Security tab, then "Report a vulnerability". Do not open a public issue for it.

## Threat model

valetkey sits between an AI agent and your ops tools. It acts with each person's own upstream credentials, and it limits what a personal access token can do with them.

### What valetkey protects against

- An agent reaching resources outside its token's scope. A token names the repositories, Jenkins jobs, Argo CD apps, log streams and metric labels it may touch. A call outside them is refused before it reaches the upstream.
- Merging on stale state. `bitbucket_pr_merge` takes `expected_source_commit` and `argocd_sync` takes `expected_revision`. Both refuse when the upstream has moved, and `argocd_sync` then syncs exactly the commit it checked.
- Unbounded repeated writes. Each token has a write limit per hour, 20 by default.
- Silent actions. Every call that reaches a tool, refused ones included, is written to the audit log and shown on `/activity`. A call to a tool outside a token's list is rejected by the MCP layer before valetkey's handler and is not logged.
- An agent seeing a tool definition you did not approve. For MCP servers people add, `tools/list` shows the approved snapshot of each server's tools. A changed description or a new tool stays hidden until the person approves it, and approving stores the list that was shown.
- A user's MCP server reaching internal addresses. See "The network guard" below.
- A sign-in open to a whole identity provider. The server will not start without `ALLOWED_DOMAINS` or `ALLOWED_EMAILS`, and for Google, when the match comes from `ALLOWED_DOMAINS`, it also checks the `hd` claim so a consumer account with a company address is refused. A match from `ALLOWED_EMAILS` does not use that check.

### What valetkey does not protect against

- Upstream credentials that are themselves too broad. valetkey acts with the user's own credentials, so the scope is the only thing between an agent and everything that credential can do. Give tokens narrow scopes, and connect narrow credentials where the upstream allows it, such as a Bitbucket repository access token.
- What a proxied tool does. Tools from a user's own MCP servers have no resource scope, because valetkey cannot interpret their arguments. A token can list them, and the write limit, dry run and audit log apply, but nothing limits which resources they touch. A server that is malicious or compromised can also return text meant to steer the agent: its output reaches the agent unfiltered.
- A server swapped under the same name. Token grants for proxied tools are by name. If a person removes a server and adds another with the same name, tokens that listed `name__tool` apply to the new server's tool.
- A malicious valetkey administrator. Whoever runs the server and its database can read the audit log, change the code and revoke tokens.
- A compromised host. The vault key that seals stored credentials sits in the server's environment, so anyone who can read the environment and the database can open the credentials.

### Notes for operators

- Upstream credentials are sealed with `VAULT_KEY` before they reach the database. Keep that key out of the database backup.
- The ID token comes straight from the identity provider's token endpoint over TLS, so valetkey checks its claims (`iss`, `aud`, `email`, `email_verified`) but does not verify the signature, as OpenID Connect Core 3.1.3.7 allows. For that reason valetkey refuses to start with a plain-http `OIDC_ISSUER` unless its host is loopback.
- Tool arguments are stored in the audit log as sent, cut to 4 KiB. That includes Jenkins build parameters, so do not pass secrets as build parameters.
- Personal access tokens are shown once, when you create them. Revoke one on `/tokens` when you no longer need it.
- `OIDC_TRUST_UNVERIFIED_EMAIL=true` makes valetkey accept whatever email the identity provider reports. Entra's `email` claim is not verified and can change over time. With this setting, prefer `ALLOWED_EMAILS`, or an issuer restricted to your own tenant.

### The network guard

valetkey makes outbound requests to servers that users choose, so every request to one goes through a single guarded client: tool calls, OAuth discovery, client registration, token exchange and refresh.

- https only. http is allowed only for hosts in `UPSTREAM_ALLOW_HOSTS`.
- The address is checked when the connection opens, after DNS resolves, so a name that changes its answer cannot slip through. Refused: loopback, private, link-local (including cloud metadata), CGNAT, documentation, NAT64, 6to4, Teredo, SIIT and similar ranges. A name resolves to at most 3 addresses, tried under one 10 second connect deadline.
- Up to 3 redirects, each one checked again. A redirect to another origin is refused, so credentials go only to the server's own origin.
- `HTTP_PROXY` and similar variables are ignored.
- Responses are cut off at 1 MiB.
- `UPSTREAM_ALLOW_HOSTS` takes exact host names. An allowed name trusts whatever its DNS returns, private addresses included, and is reachable on any port. Only the operator sets it.
- On an IPv6-only network with NAT64, IPv4-only servers cannot be reached, because `64:ff9b::/96` is refused.

The authorization endpoint of an OAuth server is only a redirect for the person's browser. valetkey does not fetch it.

### Upstream credentials and OAuth

- The caller's bearer token is never sent to an MCP server. Only the server's own credential is, and only to its own origin.
- Credentials for a user's MCP servers are sealed with `VAULT_KEY` like the others.
- The OAuth `state` carries only the server's ID and a nonce, signed and tied to the browser session. The PKCE verifier and any client secret are kept sealed in the stored credentials, never in a URL.
- Pages show a plain reason when a server fails, never raw error text or the addresses a name resolved to.
