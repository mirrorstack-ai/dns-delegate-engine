# dns-delegate-engine

The service that holds MirrorStack's delegated DNS credentials — and nothing else.

When you connect a custom domain to [MirrorStack](https://mirrorstack.ai), you can
create the DNS records by hand, or you can authorize us to create them for you.
The second option asks your DNS provider for a write-capable grant on your zone.
That is a real credential, and you are right to want to know what it can do.

This repository is the answer. It is public so that the question **"could
MirrorStack take our company website down?"** can be settled by reading code
instead of by trusting a support reply.

---

## Status, before anything else

This service is **being rebuilt**, and the reason is a defect in what it does
today rather than a feature we want.

Today it takes a list of DNS records from MirrorStack's private half and
publishes them, refusing anything outside the anchor. That bounds **where** we
can write. It does not bound **what** — inside your domain, the private half
picks the record and its value, and a record's value is not something containment
can constrain. So a reader of this repository cannot currently answer the
question it exists to answer.

[`docs/DESIGN.md`](docs/DESIGN.md) is the shape being built: MirrorStack's private
half sends an intent and a domain and can no longer name a record at all, the
derivation moves here, and **the record that proves you own the domain becomes
one you publish rather than one we write.**

Everything below describes what runs **today**. Where this file and the design
disagree, this file is the truth.

---

## The short version

| Question | Answer | Where to check |
|---|---|---|
| Can it delete a DNS record? | **No.** There is no delete call anywhere in this service. | [`internal/dnsprovider/provider.go`](internal/dnsprovider/provider.go) — the `Provider` interface has eight methods, four of which reach the network, and none of them removes anything |
| Can it touch a name you didn't see? | **No.** Every record must sit at or under the anchor — the exact hostname you proved you own — or the whole plan is refused. | [`internal/dnsplan/plan.go`](internal/dnsplan/plan.go), `NewSnapshot` and `Contains` |
| Can it touch `www`, your apex, or your MX? | **No**, unless the domain you connected *is* that name. Connecting `shop.example.com` cannot reach `example.com`, `www.example.com`, or your mail records. | [`TestContainmentInACustomerZone`](internal/dnsplan/plan_test.go) asserts exactly this |
| Can it write an A record or an MX record? | **No.** The plan vocabulary is `CNAME` and `TXT` only. | `NormalizeRecords`, and [`TestNormalizeRecordsRejectsUnsupportedTypes`](internal/dnsplan/plan_test.go) |
| Can it take over a name you're already using? | **No.** If something already answers there and it isn't ours, the publish is refused and names what it found. You delete it yourself and authorize again. | [`ErrNameInUse`](internal/reconcile/reconcile.go) |
| Can what gets written differ from what you approved? | **Not on the pass you authorized** — a SHA-256 over the record set is taken before you consent and re-checked before anything is written. Later passes publish records that did not exist yet, so there was nothing to approve; those are bounded by the anchor. And the check is **skipped if the caller omits the digest**, so it defends against a bug in the private half, not against the private half. | `Snapshot.Digest`, `Snapshot.Validate` |
| **Can the private half write a record you did not ask for?** | 🔴 **Yes, today, inside your domain.** Containment bounds a record's name, never its value. This is the defect the rebuild exists to fix. | [`docs/DESIGN.md`](docs/DESIGN.md) |
| How long does the credential live? | A platform-domain grant is held **24 hours**, and is not cut short when the last record lands. An app-domain grant is **standing**, because every new app you deploy needs a record created for it — you can revoke it at your provider at any time. | See *Grant lifetimes* below |

If you want to check one thing, check `Contains` in
[`internal/dnsplan/plan.go`](internal/dnsplan/plan.go). It is six lines, and it is
the boundary — and then read [`docs/DESIGN.md`](docs/DESIGN.md) for why six lines
bounding a *name* is not enough, and what replaces it.

For the complete list of what lands in your zone, including the two records that
are relayed verbatim from AWS and Cloudflare rather than chosen by anyone at
MirrorStack, see [`docs/RECORDS.md`](docs/RECORDS.md).

---

## Why the boundary is here and not in the app

MirrorStack's application platform is a private repository, and publishing it
would not answer your question anyway — you would have to read all of it to be
sure none of it reached your zone.

So the credential does not live there. `api-platform` never holds a DNS provider
token, and this service never derives what records to create. The two halves are
split on purpose:

```
api-platform  (private)                     dns-delegate-engine  (this repo, public)
──────────────────────────                  ─────────────────────────────────────────
authenticates the operator                  holds the provider credential
works out which records are needed
                          ──── plan ───►    ✅ refuses any record outside the anchor
                                            ✅ refuses any plan whose digest moved
                                            ✅ creates and updates; never deletes
                                            ✅ one bounded window, then it stops
                                                   │
                                                   ▼
                                            your DNS provider
```

The call only ever goes left to right. A bug — or a bad actor — on the private
side cannot get `www.example.com` written, because the plan it sends is checked
here against the name you proved you own, and refused if it does not fit.

That containment check is the reason this repository is small enough to read.

---

## What "forward-only" means, and what it costs you

This service creates records and updates records. It never deletes one.

That is not caution for its own sake. No DNS provider in scope offers a
*conditional* mutation — there is no "delete this record, but only if it is still
exactly the one I wrote". So a rollback could not tell the difference between
undoing our own write and overwriting an edit you made thirty seconds ago. Given
those two options, we do not roll back.

**The trade-off is honest:** if a publish fails halfway, some of the approved
records exist and some do not. Nothing of yours has been changed. Re-authorizing
re-reads the current state and finishes the job; it converges.

The other rule worth knowing: when a write returns an ambiguous answer — a
timeout, a rate limit, a 5xx — this service **re-reads** to find out what
happened. It never retries the write. A retry is how one record becomes two.

---

## Grant lifetimes

There are two kinds of grant, and they are deliberately different.

**Platform domain** (your MirrorStack console at your own hostname) — the record
set is known up front and finite. The grant is held for at most **24 hours**,
long enough to cover certificate validation records that your provider has not
published yet, and then it is released.

**App domain** (`*.apps.yourcompany.com`, where each app you deploy gets a
hostname) — the record set is *not* known up front, because the apps have not
been created yet. This grant is standing: it exists so that deploying a new app
does not require a fresh authorization each time.

A standing grant is a real trade-off, and it is the one to think hardest about.
Two things bound it: the anchor containment above — the grant can only ever reach
names under the app domain you delegated — and your provider's own revocation,
which works whether or not we are involved. Revoking at the provider is always
available to you and takes effect immediately.

---

## Multiple providers

Cloudflare is the first provider. The structure is built for others.

The split is deliberate: everything that *bounds* a write lives above the
provider interface, in code every provider shares. An adapter supplies the
provider-shaped parts — how a zone is found, the wire format, how that API spells
"already exists" and "this may or may not have applied", how it quotes a TXT
value. It cannot opt out of a safety rule, because it never sees one.

`internal/dnsprovider/provider.go` is the whole seam.

---

## Layout

```
dns-delegate-engine/
├── cmd/dns-delegate-api/       Lambda: the RPC surface api-platform calls
├── internal/
│   ├── dnsplan/                the authorization boundary — containment, digest, normalization
│   ├── dnsprovider/            the provider seam; safety rules live ABOVE it
│   ├── reconcile/              the publisher, and every safety rule
│   ├── provider/cloudflare/    the first adapter
│   ├── grant/                  the RPC surface: authorize, publish, revoke
│   └── shared/                 the OAuth client, the sealing keyset, the JSON envelope
├── docs/DESIGN.md              the shape this is being rebuilt into
├── docs/RECORDS.md             every record we can write, in full
└── Makefile                    make check — vet, build, race tests, arm64 cross-build
```

**There is no database.** This service owns no table, opens no connection, and
ships no migration. MirrorStack stores every row — including your held grant, as
ciphertext — and this service holds the key and the OAuth client with nowhere to
persist anything. You do not have to reason about a schema to audit what can
reach your zone.

🔴 **One correction to that, because an earlier version of this file overstated
it.** It said MirrorStack holds the ciphertext "as ciphertext it holds no key
for". That is a property of the **code** and not yet of the **permissions**: the
private half's account role still has read access to both the sealing keyset and
the OAuth client, left behind by the pre-cutover in-process path that this
service replaced. No code uses it — the delegated path runs entirely here — but a
granted capability is not the same as an unused one, and this repository is not
the place to describe a permission as absent because nothing exercises it.
Removing those grants is the outstanding half of the cutover.

## Running the checks yourself

```bash
make check
```

No network, no database, no Cloudflare account. The properties this README
claims are asserted by tests that anyone who clones the repository can run.

## License

[FSL-1.1-ALv2](LICENSE) — converts to Apache 2.0 two years after release.
