# Contributing

## Run the tests

SQLite is the default. The tests create a database file in a temporary directory:

```sh
go vet ./...
go test ./...
```

To run the same tests on Postgres, point `TEST_DATABASE_URL` at a server you can create databases on. Each test makes its own throwaway database:

```sh
TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./...
```

CI runs both. `CGO_ENABLED=0` must keep building, so use pure-Go libraries only.

## The write-tool contract

Every tool marked `Destructive` must meet all four rules. Tick them in your pull request description.

- [ ] Its integration implements `tools.Scoper`. A registry test fails otherwise.
- [ ] It takes a state precondition where the upstream offers one (`expected_source_commit` for a merge, `expected_revision` for a sync) and refuses when the state does not match.
- [ ] It returns a handle the caller can use, such as `build started: #124 <url>` or `merged <hash>`, not a bare "ok".
- [ ] A read tool exists to wait on or verify the result (`jenkins_build_wait`, `argocd_watch`, `bitbucket_pr_get`).

Refusals use `tools.Refuse`, which produces `refused: <tool>: <reason>`. Agents read that text, so say what is allowed as well as what failed.

## Add an integration

1. Implement `tools.Integration` in `internal/integrations/<name>`.
2. Implement `tools.Scoper` (`ScopeKey`, `ParseScope`, `CheckScope`) so a token can limit it. Optionally implement `tools.Helper` to add help text to the connect page.
3. Add the system name to `config.Systems` in `internal/config/config.go`. That makes `<SYSTEM>_URL` and `<SYSTEM>_INSECURE` work.
4. Register it in `integrations()` in `cmd/valetkey/main.go`.
5. Add the two variables to `.env.example` and the README tables.
6. Test scope checks with queries and arguments built to slip past them, not only the happy path.

## Commits

One logical change per commit, with a subject in the form `type(scope): what changed`, for example `feat(tools): limit personal access tokens to their tools`. Write commit messages, comments, docs and identifiers in English.
