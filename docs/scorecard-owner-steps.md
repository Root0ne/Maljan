# OpenSSF Scorecard: the owner's steps

What the repository cannot do for itself on
<https://scorecard.dev/viewer/?uri=github.com/Root0ne/Malspark>. The checks
the code can satisfy are satisfied by the files on `dev`; Scorecard reads the
default branch, so every one of them counts only after `dev` is promoted to
`main`. The Scorecard workflow runs on each push to `main` and weekly.

## 1. The Scorecard token (Branch-Protection reads -1 without it)

The workflow's own token cannot read classic branch protection, so the check
answers "?" (-1). A fine-grained personal access token lets it read the rules:

1. Create a fine-grained token at
   <https://github.com/settings/personal-access-tokens/new>:
   - Token name: `OpenSSF Scorecard Action - Root0ne/Malspark`
   - Expiration: custom, one year ahead (the maximum)
   - Repository access: *Only select repositories* → `Root0ne/Malspark`
   - Repository permissions: **Administration: Read-only** (Metadata:
     Read-only is added with it). Nothing else; the Webhooks permission is
     only for an experimental check.
2. Add it as a repository secret named **`SCORECARD_TOKEN`**
   (*Settings → Secrets and variables → Actions → New repository secret*).
3. Renew it before it expires; GitHub e-mails a reminder. Without the secret
   the workflow falls back to its own token and the check returns to -1.

The token can read every repository setting the Administration permission
covers; it cannot change any. Repository rulesets (*Settings → Rules →
Rulesets*) are readable without the token: moving the branch rules to a ruleset
is the alternative to holding a token at all.

## 2. Branch protection on `main` and `dev`

Scorecard scores the default branch (`main`) in tiers; a tier counts only when
every tier below it is complete. Its state today and what each tier needs:

| Tier | Requirement | `main` today | `dev` today |
|---|---|---|---|
| 1 (3/10) | Block force pushes | on | on |
| 1 | Block deletion | on | on |
| 2 (6/10) | At least 1 approving review | **off** (0 required) | off |
| 2 | Pull request required before merging | on | on |
| 2 | Branch up to date before merging | **off** | off |
| 2 | Approval of the most recent reviewable push | **off** | off |
| 3 (8/10) | At least 1 required status check | on (8 checks) | on (8 checks) |
| 4 (9/10) | At least 2 approving reviews | off | off |
| 4 | Review from code owners | **off** | off |
| 5 (10/10) | Dismiss stale approvals on new commits | on | on |
| 5 | Include administrators | on | on |

To enable now, on `main` and `dev` (*Settings → Branches → Edit*):

- **Require branches to be up to date before merging.** A pull request is
  then tested against the branch as it will be after the merge. On `dev`,
  where Dependabot pull requests land in batches, each one needs an update
  before it can merge; it is worth that on `main` in any case.

To enable only once a second maintainer with write access exists:

- **Require approvals: 1**, then **Require approval of the most recent
  reviewable push**, completing tier 2. Tier 3 is already met, so this alone
  takes the check to 8.
- **Require approvals: 2** and **Require review from Code Owners** (with that
  person in `.github/CODEOWNERS`) for tier 4, and with tier 5 already on, 10.

With one maintainer and *Include administrators* on, a required approval
blocks every merge: the author cannot approve their own pull request. Do not
work around it with a second account, a bot or an AI reviewer approving; that
is the review the check exists to measure. Until then the expected score is
3 plus partial credit inside tier 2.

## 3. The Best Practices badge (CII-Best-Practices reads 0)

1. Promote `dev` and push the first release tag (RELEASING.md), so the
   release criteria have a release to point at.
2. Sign in at <https://www.bestpractices.dev/> with GitHub, choose *Get your
   badge now*, and enter `https://github.com/Root0ne/Malspark`.
3. Fill in the passing form from `docs/bestpractices-answers.md`, answer the
   two developer-knowledge criteria yourself, and submit. A criterion marked
   *Unmet* there stays unmet until the change it names is made.
4. Add the badge to the README (the line the badge page gives, with the
   project's number).

Scorecard reads the badge by the repository URL: *in progress* scores 2,
passing 5, silver 7, gold 10. Silver and gold ask for things a
one-maintainer project cannot show (two-person review, a bus factor of two or
more), so passing is the honest ceiling for now.

## 4. Code-Review and Contributors

Neither can be raised with code, and neither is to be gamed.

- **Code-Review** looks at the last ~30 merged changes and counts one as
  reviewed when a person other than the author approved it on GitHub, or a
  person other than the committer merged it. Review by bots, AI included,
  does not count. Every human change merged unreviewed costs 7 points, more
  than one 10. It rises only when a second human reviews and approves pull
  requests.
- **Contributors** reads the *Company* field on the GitHub profile of each
  author among the last 30 commits; 10 needs three organisations, each with
  at least five of those commits. The owner's profile has no company today:
  set it to the organisation you actually work for
  (<https://github.com/settings/profile>). More organisations come only from
  contributors who work elsewhere.

## 5. After the first release

- **Packaging** and **Signed-Releases** read the release workflow's results:
  Packaging a successful run that published images, Signed-Releases the
  signatures (`*.sigstore.json`) and the provenance (`*.intoto.jsonl`) on each
  of the last releases. Both count from the first `v*` tag.
- Set each `ghcr.io/root0ne/malspark-*` package to public and link it to the
  repository (RELEASING.md, step 6).
- Set the repository's website field to <https://malspark.com>.

## 6. Vulnerabilities

The check counts open OSV advisories in the lockfiles (10 minus one point
each). It recovers as the dependency upgrades land. An advisory that does not
affect the project, typically one with no fixed version, is recorded with its
reason in an `osv-scanner.toml` beside the lockfile rather than left open.
