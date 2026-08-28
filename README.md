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

<table>
<thead>
<tr>
<th width="22%">Question</th>
<th width="50%">Answer</th>
<th width="28%">Where to check</th>
</tr>
</thead>
<tbody>
<tr>
<td>Can it delete a DNS record?</td>
<td><strong>No.</strong> There is no delete call anywhere in this service.</td>
<td><a href="internal/dnsprovider/provider.go"><code>provider.go</code></a> — the <code>Provider</code> interface has eight methods, four of which reach the network, and none of them removes anything</td>
</tr>
<tr>
<td>Can it touch a name you didn't see?</td>
<td><strong>No.</strong> Every record must sit at or under the anchor — the exact hostname you proved you own — or the whole plan is refused.</td>
<td><a href="internal/dnsplan/plan.go"><code>plan.go</code></a>, <code>NewSnapshot</code> and <code>Contains</code></td>
</tr>
<tr>
<td>Can it touch <code>www</code>, your apex, or your MX?</td>
<td><strong>No</strong>, unless the domain you connected <em>is</em> that name. Connecting <code>shop.example.com</code> cannot reach <code>example.com</code>, <code>www.example.com</code>, or your mail records.</td>
<td><a href="internal/dnsplan/plan_test.go"><code>plan_test.go</code></a> asserts exactly this</td>
</tr>
<tr>
<td>Can it write an A record or an MX record?</td>
<td><strong>No.</strong> The plan vocabulary is <code>CNAME</code> and <code>TXT</code> only.</td>
<td><code>NormalizeRecords</code>, and <a href="internal/dnsplan/plan_test.go"><code>plan_test.go</code></a></td>
</tr>
<tr>
<td>Can it take over a name you're already using?</td>
<td><strong>No.</strong> If something already answers there and it isn't ours, the publish is refused and names what it found. You delete it yourself and authorize again.</td>
<td><a href="internal/reconcile/reconcile.go"><code>ErrNameInUse</code></a></td>
</tr>
<tr>
<td>Can what gets written differ from what you approved?</td>
<td><strong>Not on the pass you authorized</strong> — a SHA-256 over the record set is taken before you consent and re-checked before anything is written. Later passes publish records that did not exist yet, so there was nothing to approve; those are bounded by the anchor. And the check is <strong>skipped if the caller omits the digest</strong>, so it defends against a bug in the private half, not against the private half.</td>
<td><code>Snapshot.Digest</code>, <code>Snapshot.Validate</code></td>
</tr>
<tr>
<td><strong>Can the private half write a record you did not ask for?</strong></td>
<td>🔴 <strong>Yes, today, inside your domain.</strong> Containment bounds a record's name, never its value. This is the defect the rebuild exists to fix.</td>
<td><a href="docs/DESIGN.md"><code>docs/DESIGN.md</code></a></td>
</tr>
<tr>
<td>How long does the credential live?</td>
<td>A platform-domain grant is held <strong>24 hours</strong>, and is not cut short when the last record lands. An app-domain grant is <strong>standing</strong>, because every new app you deploy needs a record created for it — you can revoke it at your provider at any time.</td>
<td>See <em>Grant lifetimes</em> below</td>
</tr>
</tbody>
</table>

If you want to check one thing, check `Contains` in
[`internal/dnsplan/plan.go`](internal/dnsplan/plan.go). It is six lines, and it is
the boundary — and then read [`docs/DESIGN.md`](docs/DESIGN.md) for why six lines
bounding a *name* is not enough, and what replaces it.

For the complete list of what lands in your zone, including the two records that
are relayed verbatim from AWS and Cloudflare rather than chosen by anyone at
MirrorStack, see [`docs/RECORDS.md`](docs/RECORDS.md).

---

## What actually happens when you connect a domain

This is today's flow, defect included. Read step 2 first: **the record list is
chosen entirely by MirrorStack's private half**, and the only thing this service
checks is that each name sits under your domain.

```mermaid
sequenceDiagram
    autonumber
    actor You
    participant Console as MirrorStack console<br/>(private)
    participant Engine as dns-delegate-engine<br/>(this repository)
    participant CF as Your DNS provider
    participant ACM as AWS certificate manager
    participant Edge as MirrorStack edge

    You->>Console: connect example.com
    Console->>Console: derive the record list
    Console-->>You: here are the records, and their SHA-256

    You->>CF: authorize (zone.read, dns.write — one zone)
    CF-->>Engine: authorization code

    Note over Engine: refuse unless every NAME is at or<br/>under example.com. The VALUES are<br/>not checked against anything.
    Engine->>CF: ownership TXT + routing CNAMEs
    Engine-->>Console: sealed credential, held 24h

    loop every 5 minutes, for up to 24 hours
        Console->>Console: re-derive the record list
        Console->>ACM: has the validation record appeared?
        Console->>Edge: has the custom hostname minted its proofs?
        Console->>Engine: publish what is new
        Engine->>CF: _9f8c….account.example.com, _acme-challenge.account.example.com,<br/>_cf-custom-hostname.account.example.com
    end

    Note over Engine: 24 hours after you authorized
    Engine->>CF: revoke the credential
```

Three things that diagram makes obvious, and which the rebuild changes:

- **The loop belongs to the private half.** Every re-derivation, every decision
  about what to publish next, happens where you cannot read it. This service is
  called once per pass and told what to write.
- **The ownership TXT is written by us, in step 7.** It is also what gates the
  custom hostname in step 13 — so the record that is supposed to prove you own
  the domain is satisfied by our own write.
- **Three records arrive late** because they are answers from AWS and Cloudflare
  that do not exist when you authorize. That is why the credential is held rather
  than spent once, and it is not going to change.

[`docs/DESIGN.md`](docs/DESIGN.md) has the same diagram for the shape being built,
where the loop, the derivation and the proof all move.

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
