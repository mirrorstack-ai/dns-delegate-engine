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

## The short version

| Question | Answer | Where to check |
|---|---|---|
| Can it delete a DNS record? | **No.** There is no delete call anywhere in this service. | [`internal/dnsprovider/provider.go`](internal/dnsprovider/provider.go) — the `Provider` interface has four methods and none of them removes anything |
| Can it touch a name you didn't see? | **No.** Every record must sit at or under the anchor — the exact hostname you proved you own — or the whole plan is refused. | [`internal/dnsplan/plan.go`](internal/dnsplan/plan.go), `NewSnapshot` and `Contains` |
| Can it touch `www`, your apex, or your MX? | **No**, unless the domain you connected *is* that name. Connecting `shop.example.com` cannot reach `example.com`, `www.example.com`, or your mail records. | [`TestContainmentInACustomerZone`](internal/dnsplan/plan_test.go) asserts exactly this |
| Can it write an A record or an MX record? | **No.** The plan vocabulary is `CNAME` and `TXT` only. | `NormalizeRecords`, and [`TestNormalizeRecordsRejectsUnsupportedTypes`](internal/dnsplan/plan_test.go) |
| Can what gets written differ from what you approved? | **No.** A SHA-256 over the exact record set is taken before you authorize and re-checked before anything is written. | `Snapshot.Digest`, `Snapshot.Validate` |
| How long does the credential live? | A platform-domain grant is held at most **24 hours**. An app-domain grant is **standing**, because every new app you deploy needs a record created for it — you can revoke it at your provider at any time. | See *Grant lifetimes* below |

If you want to check one thing, check `Contains` in
[`internal/dnsplan/plan.go`](internal/dnsplan/plan.go). It is six lines, and it is
the boundary.

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
└── Makefile                    make check — vet, build, race tests, arm64 cross-build
```

**There is no database.** This service owns no table, opens no connection, and
ships no migration. MirrorStack stores every row — including your held grant,
as ciphertext it holds no key for. This service holds the key and the OAuth
client, and has nowhere to persist anything. Neither half can act alone, and
you do not have to reason about a schema to audit what can reach your zone.

## Running the checks yourself

```bash
make check
```

No network, no database, no Cloudflare account. The properties this README
claims are asserted by tests that anyone who clones the repository can run.

## License

[FSL-1.1-ALv2](LICENSE) — converts to Apache 2.0 two years after release.
