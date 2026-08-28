# Do the tests actually bind the claims?

A test suite that passes tells you the code does what the tests ask. It does not
tell you the tests ask for anything.

This repository's tests are its evidence — a customer's developer is being
invited to read them instead of trusting us — so "are these tests decorative?" is
not a code-quality question here. It is the question.

**Mutation testing answers it mechanically.** Break an invariant on purpose. If
no test fails, that invariant was unguarded, whatever the comments said.

---

## How to reproduce this

Every row below is one edit to one line, run against `go test`. There is no tool
to install:

```bash
git stash list            # start clean — a mutation is an edit you must be able to undo
# edit the line
go test ./...             # judge by the EXIT CODE
git checkout -- <file>    # put it back
```

🔴 **Judge by the exit code, never by grepping for `ok`.** See the last section —
this is not hypothetical advice.

---

## The pass

Run 2026-08-28 against `test/security-properties`.

| # | invariant broken | how | verdict |
|---|---|---|---|
| 1 | `Contains` requires a **label boundary** | drop the leading dot: `HasSuffix(name, anchor)` | 🔴 **survived** `./internal/dnsplan` · killed tree-wide. **See finding 1.** |
| 2 | the record vocabulary is `CNAME`/`TXT` only | admit `A` in `NormalizeRecords` | killed — `TestNormalizeRecordsRejectsUnsupportedTypes` |
| 3 | the ownership proof is never published by us | let `Publishable()` return `SourceCustomer` items | killed — `TestOwnershipIsTheCustomersAndIsNeverPublishable`, `TestPublishableAndManualPartitionTheItems` |
| 4 | a customer-zone record is never proxied | `Proxied: true` on the routing record | killed — 3 tests across `intent` and `derive` |
| 5 | a sealed grant is bound to its row | `grantAAD` returns a constant | killed — `TestGrantAADBindsToTheRow`, `TestGrantAADGolden` |
| 6 | `Complete` requires a digest | `if false` on the empty check | killed — `TestCompleteRefusesAnEmptyExpectDigest` |
| 7 | a failed lookup is **never** "absent" | return `StateAbsent` on a resolver error | killed — `TestProofUnknownReturnsTheErrorAndIsNeverAbsent`, `TestALookupThatDidNotCompleteIsNeitherProvenNorWithdrawn`, `TestAResolverFailureStillWarnsAndStillPublishes` |
| 8 | an authorization is short-lived | `AuthStateTTL` → 100000h | killed — `TestOpenAuthStateEnforcesItsWindow` |
| 9 | the relay reserve bounds what can be merged | `MaxRelayed` → 1<<20 | killed — `TestALargeReissuedCertificateEstateStillRelays` |
| 10 | a pass that could not look must not write | fold every `checkProof` error into a warning | killed — `TestAPassThatCouldNotLookRefusesRatherThanWriting` (**this mutation is how that test was written**; it publishes all eight records) |
| 11 | a slug is one label | remove the explicit dot check | **equivalent mutant** — see finding 2 |
| 12 | the consent token is compared in constant time | `hmac.Equal` → `==` | **unkillable by behavioural tests** — see finding 3 |

---

## Finding 1 · a test that read correct and asserted nothing

Mutation 1 is the one that made this exercise worth running.

`README.md` points at `internal/dnsplan/plan_test.go` as the evidence for its
most-quoted claim — *"Can it touch `www`, your apex, or your MX? No."* The
relevant test, `TestContainmentRefusesEscape`, contains a case labelled:

```go
{"a suffix-confusion neighbour", "evilexample.com"},
```

That case cannot fail. The test's anchor is `app.example.com`, and
`evilexample.com` does not end in `app.example.com` **with or without** the dot —
so it was never a near-miss for that anchor. The name of the case describes a
scenario the fixture does not create.

Deleting the leading dot from `Contains` therefore survived this package's entire
suite. The property did hold in practice, but only because tests in
`internal/lane` and `internal/relay` happened to exercise it as a side effect —
which is not a bound anyone can rely on. Deleting an unrelated test elsewhere
would have left the claim unguarded, and nothing would have said so.

**Closed** by `TestContainsRequiresALabelBoundary`, which asserts `Contains`
directly on names that genuinely end with the anchor but break at the wrong
character — `evilexample.com`, `notexample.com`, `myshop.example.com` — plus the
normalization spellings (case, trailing dot) that could open the same hole.
`FuzzContainsNeverEscapesTheAnchor` now covers the general shape.

## Finding 2 · an equivalent mutant, recorded so it is not mistaken for a gap

Removing the explicit dot check from `ValidateSlug` survives everything. That
looks like finding 1 and is not: `labelReason` already rejects a dot, because a
dot is not an LDH character. Verified by probing the mutated build directly —
`ValidateSlug("a.b")` still fails.

The check is redundant defence-in-depth with a better error message. Nothing to
close. It is listed because a survivor with no explanation beside it reads as an
open hole, and this one is not.

## What fuzzing found that mutation did not

The two methods are complementary and it showed. Mutation testing asks *"is this
invariant guarded?"*; fuzzing asks *"is this invariant true?"* — and the second
question had four answers nobody expected. All four are fixed in the parent
branch, and the targets that found them are in this one:

| found by | defect |
|---|---|
| `FuzzDigestIsStableAndBinding` | 🔴 **the digest did not bind record bytes.** `json.Marshal` silently folds invalid UTF-8 to U+FFFD, so `"token-\xff"` and `"token-\xfe"` produced one SHA-256 |
| `FuzzContainsNeverEscapesTheAnchor`, plus three targets in `observe` and `relay` | `NormalizeName` was not idempotent — the root-dot trim uncovered a space the space-trim had already run past, so a plan accepted at authorize time was refused at publish time |
| `FuzzNewSnapshotRefusesEveryEscape` | `MaxRecordIdentity` was enforced on read and not on write — the same accept-then-refuse stranding, reachable with plain ASCII |
| `FuzzEveryDerivedPlanIsSafe` (as an observation, not a failure) | a reserved suffix written with a **leading dot** passed the malformed-list guard and then matched nothing |

Note what mutation testing could not have caught here. Every one of these is a
case where the code does what its tests ask **and the invariant is still false**
— there was no line to break, because the missing check was never written. A
mutation pass over the same code returns a clean sheet.

The reverse also held: fuzzing would never have found the decorative test in
finding 1, because the property it failed to guard was true the whole time.

## Finding 3 · what mutation testing cannot tell you

Mutation 12 replaces the constant-time comparison with `==`. Every test passes,
and every test *should* pass — the two are behaviourally identical, and the
difference is a timing side channel no unit test observes.

This is the honest limit of the method. It says nothing about properties that are
not expressed as behaviour: timing, memory zeroing, ordering under concurrency.
Those still need review, and are called out in the code at each site.

---

## 🔴 The verifier lied first

The first version of the harness used to produce this table reported mutation 3 —
publishing the customer's ownership proof, the exact defect the rebuild exists to
prevent — as **survived**. It had not survived; two tests failed.

The harness decided the verdict by grepping the output for `ok`. `go test ./...`
prints an `ok` line for every package that passes, so any run with at least one
healthy package matched, no matter what else failed.

It is worth writing down for two reasons. It is the trap this whole document is
about, one level up: a checking tool is a claim too, and this one asserted the
strongest safety property in the repository was unguarded when it was fine — and
would just as happily have asserted the reverse. And it is the reason the
reproduction steps above say to judge by the exit code, in bold, rather than
leaving it as the obvious thing to do.

The corrected harness reads `$?`. Every verdict in the table was re-run under it.
