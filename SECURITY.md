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
- A sign-in open to a whole identity provider. The server will not start without `ALLOWED_DOMAINS` or `ALLOWED_EMAILS`, and for Google, when the match comes from `ALLOWED_DOMAINS`, it also checks the `hd` claim so a consumer account with a company address is refused. A match from `ALLOWED_EMAILS` does not use that check.

### What valetkey does not protect against

- Upstream credentials that are themselves too broad. valetkey acts with the user's own credentials, so the scope is the only thing between an agent and everything that credential can do. Give tokens narrow scopes, and connect narrow credentials where the upstream allows it, such as a Bitbucket repository access token.
- A malicious valetkey administrator. Whoever runs the server and its database can read the audit log, change the code and revoke tokens.
- A compromised host. The vault key that seals stored credentials sits in the server's environment, so anyone who can read the environment and the database can open the credentials.

### Notes for operators

- Upstream credentials are sealed with `VAULT_KEY` before they reach the database. Keep that key out of the database backup.
- The ID token comes straight from the identity provider's token endpoint over TLS, so valetkey checks its claims (`iss`, `aud`, `email`, `email_verified`) but does not verify the signature, as OpenID Connect Core 3.1.3.7 allows. For that reason valetkey refuses to start with a plain-http `OIDC_ISSUER` unless its host is loopback.
- Tool arguments are stored in the audit log as sent, cut to 4 KiB. That includes Jenkins build parameters, so do not pass secrets as build parameters.
- Personal access tokens are shown once, when you create them. Revoke one on `/tokens` when you no longer need it.
- `OIDC_TRUST_UNVERIFIED_EMAIL=true` makes valetkey accept whatever email the identity provider reports. Entra's `email` claim is not verified and can change over time. With this setting, prefer `ALLOWED_EMAILS`, or an issuer restricted to your own tenant.
