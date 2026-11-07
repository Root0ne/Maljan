### Added

- **`malspark create-admin` makes the first admin account (T-584).** It creates an account with the `admin` role, or promotes an existing one, through the API's own user model, password hashing and `DATABASE_URL`, so the first admin no longer needs an `UPDATE` in psql. A new account's password is asked for on a hidden prompt or read with `--password-stdin`, never taken from an argument; promoting an admin changes nothing and says so; an unreachable database, or one without this release's migrations, is refused with a sentence that names its host and never its password. A grant is recorded in the audit log as `auth.role.grant`. `make create-admin EMAIL=you@example.com` runs it in the stack's API container.
- **The dev targets take compose files of your own (T-584).** `COMPOSE_FILE_EXTRA=docker/local.yml make dev-up` (several files space-separated) appends each as one more `-f` after the shipped file and the dev overlay, on `dev-up`, `dev-down` and `dev-logs`. Those targets pass two `-f` files, so Compose does not read a `docker-compose.override.yml` for them; the `docker-*` targets still do.

### Documentation

- **Native development on macOS.** The development page says how WeasyPrint finds Pango and GLib from Homebrew on Apple Silicon (`DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`), and why a `make` target does not pass that variable on.
