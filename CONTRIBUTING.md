# Contributing

Thank you for helping with Maljan. This page is the short version; the
development guide in [docs/development.md](docs/development.md) has the
details.

## Before you start

- Discuss a substantial change in an issue first, so the design is agreed
  before the work is done.
- Security problems go through
  [private vulnerability reporting](SECURITY.md), never a public issue.

## Workflow

1. Branch from `dev` and open the pull request against `dev`. Only a
   promotion PR targets `main`.
2. Keep the change focused; a refactor and a feature are two PRs.
3. Run the gates locally before pushing: `make lint format-check typecheck`,
   `uv run pytest tests/`, and in `apps/web` the type-check, lint and unit
   tests. Run the named Playwright spec for any console area you touched.
4. Add or update tests for the behaviour you change, and a `CHANGELOG.md`
   entry under Unreleased when a user would notice.
5. Fill in the pull request template. CI, CodeQL and the dependency review
   must be green; a code owner reviews every change.

## Conventions

Comments explain why, never a ticket number or a date. Commit messages follow
`type(scope): summary` (`feat`, `fix`, `refactor`, `chore`, `docs`, `test`).
No headings or comments phrased as questions. No secrets, API keys or sample
hashes in the tree.

## Licence

By contributing you agree that your contribution is licensed under the
repository's [LICENSE](LICENSE).
