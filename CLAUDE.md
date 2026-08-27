# `dns-delegate-engine` — agent guide

The delegated-DNS credential boundary. This is the ONLY MirrorStack service that
holds a customer's DNS-provider grant.

> **This repository is PUBLIC.** It exists so a customer's own developers can
> settle "could MirrorStack break our website?" by reading code. Everything you
> write here is read by people outside the company, in that frame.

## The three rules that are the whole point

1. **Nothing outside the anchor.** Every record in a plan must sit at or under
   the hostname the customer proved they own. `dnsplan.Contains` is the boundary;
   `NewSnapshot` enforces it on write and `Validate` re-enforces it on read.
   Never add a caller that skips it.
2. **Never delete.** `dnsprovider.Provider` has no delete method. Adding one is a
   design change and a broken promise in the README, not a refactor.
3. **Never retry an ambiguous write.** Re-read instead. `IsAmbiguous` must fail
   TOWARD ambiguous for any error an adapter does not recognise.

## Do not put here

- Plan derivation. Working out *which* records a domain needs is MirrorStack edge
  topology — sibling roles, ACM lifecycle, the orange/grey decision — and it stays
  in `api-platform`. The public claim survives that split because containment,
  not derivation, is what bounds the blast radius. Moving derivation here would
  move exactly the topology this repository exists to leave behind.
- Migrations. The tables live in `api-platform`'s `ms_organizations` schema and
  `api-platform` owns their DDL.
- Anything that makes the repository harder to read end-to-end in an afternoon.

## The digest is a cross-repository contract

`dnsplan.Record`'s JSON tags and field order feed a SHA-256 that `api-platform`
computes BEFORE the customer authorizes and this service re-checks BEFORE it
writes. `TestGoldenDigest` here and `TestDelegatedPlanGoldenDigest` in
`api-platform` pin the same fixture to the same hex.

If that test fails, a marshalled field moved. In production that invalidates
every in-flight attempt — every customer mid-connect is told the plan changed.
Fix the drift. Do not regenerate the constant unless you are deliberately
versioning the envelope (bump `dnsplan.Version`, and expect that invalidation).

## Transport

Production: `lambda.Invoke` by alias-qualified ARN (`…:live`), IAM-gated. NOT
behind API Gateway. A refusal is returned INSIDE the `{ok,error}` envelope, never
as a Lambda function error — at the caller a function error is indistinguishable
from the engine being unreachable, and the grant lifecycle treats those
differently: one is a retry, the other can release a live customer credential.

Local: HTTP on `:8093`, gated by `X-MS-Internal-Secret` (fail-closed on empty).

## CI

- The CI job id must stay **`test`** — the org ruleset "Required CI - Go test"
  requires a check with that literal name. Renaming it leaves the required check
  permanently pending.
- `runs-on` is hardcoded `ubuntu-latest`. This repository is public; routing its
  jobs onto the self-hosted fleet via `vars.RUNNER_LABELS` would let a fork PR run
  on our hardware.

## Commit identity

Commit as **Sheng Kun Chang <nothingchang@mirrorstack.ai>**. Never as
`mirrorstack-ops[bot]`.

```bash
git config --local user.name "Sheng Kun Chang"
git config --local user.email "nothingchang@mirrorstack.ai"
```

## When you edit this repository

1. Branch off `main`: `git checkout -b <type>/<slug>` (`feat`, `fix`, `chore`,
   `docs`, `refactor`).
2. `make check` — vet, build, race tests, and the arm64 cross-build CI also runs.
3. Commit prefix `feat:` / `fix:` / `chore:` / `docs:` / `refactor:`. Co-author
   tail: `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
4. Open a PR against `main`. Never push directly to `main`.
5. `Closes #N` when a tracking issue exists.

## Core manifest pointer automation

After a PR merges to protected `main`, a successful `Publish` run triggers
`.github/workflows/notify-core-pointer.yml`, which sends this repository's main
SHA to `mirrorstack-ai/mirrorstack-core-v2`, where `mirrorstack-core-bot` opens or
updates the commit-bound pointer PR.

Do not manually edit or push the core gitlink during the normal flow. The
automation only opens a reviewable PR; it never reviews, merges, promotes, or
deploys. If the PR is missing, inspect the `Publish` and `Notify core pointer`
runs first; core's scheduled scan is the fallback.
