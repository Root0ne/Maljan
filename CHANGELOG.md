# Changelog

Notable changes to Maljan. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); dates are the day a
change landed on `main`.

## Unreleased

### Added

- **Environment-free configuration.** Every application setting — LLM
  provider, sandbox, static analyst, tool servers, agents, rate limits,
  enrichment, memory — now lives in the settings store and is edited from
  Settings → Configuration. The catalog carries each entry's type, bounds,
  choices, description and when it takes effect, and a read-only Deployment
  group shows the values the process was started with
  ([#31](https://github.com/Root0ne/Maljan/pull/31),
  [#32](https://github.com/Root0ne/Maljan/pull/32),
  [#33](https://github.com/Root0ne/Maljan/pull/33)).
- **A bootstrap contract, validated once.** The API and the worker read a small
  fixed set of process-environment variables — database, Redis, MinIO, the two
  secrets, a handful of mount paths — documented in `bootstrap.env.example`.
  Validation happens at startup and reports every problem in one
  `bootstrap: ...` line instead of failing on whichever one an import reached
  first ([#31](https://github.com/Root0ne/Maljan/pull/31)).
- **Configuration export and import.** `GET /api/v1/settings/export` produces a
  `maljan-settings/1` JSON document and `POST /api/v1/settings/import` accepts
  it, with a preview in the console. The document carries no credential:
  secrets are skipped, masks nested inside composite settings are stripped at
  any depth, server `env` values are masked, and everything omitted is listed
  in `secrets_omitted` ([#32](https://github.com/Root0ne/Maljan/pull/32)).
- **Secret storage for nested credentials.** An MCP server's `auth_token` and a
  frontier arm's `api_key` are stored as their own Fernet-encrypted rows rather
  than inside the composite value, and are merged back on read; a startup
  repair moves any that an older version left inline
  ([#33](https://github.com/Root0ne/Maljan/pull/33)).

### Changed

- The process refuses to start without a valid `SETTINGS_ENCRYPTION_KEY`, so
  there is no mode in which stored secrets sit unencrypted
  ([#31](https://github.com/Root0ne/Maljan/pull/31)).
- `APISettings` no longer discovers or reads a `.env` file; configuration comes
  from the process environment alone
  ([#31](https://github.com/Root0ne/Maljan/pull/31)).
- Pytest detection no longer consults the environment, so no variable can hand
  a real deployment the published test secret
  ([#33](https://github.com/Root0ne/Maljan/pull/33)).
- A settings reset in the console waits for its own page before touching the
  header, fixing a flaky interaction in the group editors
  ([#35](https://github.com/Root0ne/Maljan/pull/35)).
- Documentation is now a maintained set under `docs/`, and the historical
  design record — the former `docs/plans`, `docs/specs` and `docs/superpowers`
  trees — is read from git history instead of the working tree
  ([#38](https://github.com/Root0ne/Maljan/pull/38)).

### Removed

- **Tool-count limits on MCP servers.** The Ghidra tool-selection modes
  (`curated`, a fixed 20-tool allow-list; `dynamic`, a per-sample relevance cut
  capped at 40) and the `use_all_tools` override are gone, as are the radare2
  read-only allow-list and the 13-tool "essential" list for the CAPE MCP
  server. Every tool a server offers now reaches the model, minus whatever the
  operator unticks in that server's own tool list. Tool descriptions are no
  longer cut at 100 characters. A migration removes the two retired settings
  from stored server entries. Expect larger per-step prompts on a local model.
- **Legacy settings-name aliases.** The compatibility layer that translated old
  setting names into current ones is gone; the Alembic revision that renames
  operator data carries its own frozen table, as a migration should
  ([#36](https://github.com/Root0ne/Maljan/pull/36)).
- **The one-shot `.env` import.** A new deployment starts on the catalog
  defaults and is configured from the console or from a JSON export; there is
  no automatic import of a previous `.env` deployment, and the marker table it
  needed has been dropped ([#36](https://github.com/Root0ne/Maljan/pull/36)).
- **The legacy sandbox adapter.** The CLI path drives the sandbox provider
  interface directly instead of going through a compatibility shim
  ([#37](https://github.com/Root0ne/Maljan/pull/37)).
- **Two dependencies.** `fastmcp` left with the CAPE MCP wrapper script, and
  `networkx` left with the CFG orderer that was its only user
  ([#36](https://github.com/Root0ne/Maljan/pull/36)).
- Dead code found by vulture, ruff and knip, and a duplicated structural
  `deepEqual` in the settings console, now one implementation
  ([#36](https://github.com/Root0ne/Maljan/pull/36)).
- Machine-local operator scripts (`llm_server.sh`, `night_guard.sh`,
  `run_with_restarts.sh`) and the retired annotation seeder left `scripts/`;
  what remains is what the Makefile, CI and the tests call.
- Process tags in source comments — dated audit identifiers, ticket numbers and
  phase labels. The reasoning stays, the bookkeeping goes
  ([#38](https://github.com/Root0ne/Maljan/pull/38)).

### Fixed

- **The Ghidra connection test proves the token.** The probe read the
  unauthenticated health endpoint, so a wrong bearer token passed the test and
  every job then failed with 401 on the tool schema. It now fetches the schema
  itself and lists the tools it found.

### Upgrading

An existing `.env` deployment is not migrated automatically. Move the bootstrap
variables into the process environment (or `docker/.env` and `bootstrap.env`),
start the stack, and enter the remaining settings once in Settings →
Configuration — or import a JSON export from another instance. Keep
`SETTINGS_ENCRYPTION_KEY` stable: there is no re-encryption step, and a changed
key makes every stored secret unreadable. See
[docs/configuration.md](docs/configuration.md).

A JSON export taken before the tool-selection modes were removed may carry
`core.static.ghidra.tool_selection`, `core.static.r2.tool_selection` or the
`use_all_tools` counterparts; the import refuses keys the catalog no longer
knows, so delete those entries from the file first. Stored overrides are
cleaned up by the migration.
