# Every record MirrorStack can write in your zone

This is the complete reference. If a record is not described here, no code path
in this service can produce it — the plan vocabulary is `CNAME` and `TXT` only,
and every record must sit at or under the anchor you proved you own.

The tables below are written against
[`dnsplan.Classify`](../internal/dnsplan/purpose.go), and the examples in
[`internal/dnsplan/example_test.go`](../internal/dnsplan/example_test.go) print
real plans through it. Those are `go test` examples: if this document and the
code disagree, the build fails.

---

## The anchor

The **anchor** is the exact hostname you proved you own. It is the only bound on
what a delegated write can reach, so it is worth being precise about:

| You connect | The anchor is | We can write at | We can never write at |
|---|---|---|---|
| `example.com` | `example.com` | `example.com`, `account.example.com`, `_acme-challenge.api.example.com`, … | anything not ending in `.example.com` |
| `shop.example.com` | `shop.example.com` | `shop.example.com` and below | `example.com`, `www.example.com`, `mail.example.com` |
| `example.app` (app domain) | `example.app` | `*.example.app`, `_acme-challenge.blog.example.app`, … | anything outside `example.app` |

The suffix is matched with a leading dot, so `evilexample.com` is **not** treated
as being under `example.com`. A wildcard record `*.<anchor>` is under the anchor
and is allowed.

The anchor is sealed into the credential as AES-GCM associated data, so it cannot
be widened after you consent — see [`GrantAAD`](../internal/grant/service.go) and
the README section *"But the private side chooses the anchor"*.

---

## Record 1 — ownership

```
_mirrorstack-challenge.<your-domain>   TXT   <opaque token>
```

**One per connected domain**, at the anchor itself. It proves the domain is
yours before anything else happens.

Everything downstream is gated on it: MirrorStack will not create a custom
hostname at the edge until a public DNS lookup for this name returns the token,
and no certificate record can exist before a custom hostname does. That ordering
is not policy, it is the reason the sequence in the README cannot run backwards.

**Retained.** Keeping a spent proof costs nothing, and a re-check months later
finds it. Deleting it does nothing today.

---

## Record 2 — routing

```
account.<your-domain>   CNAME   <the MirrorStack endpoint that serves it>
*.<your-app-domain>     CNAME   <the MirrorStack endpoint that serves it>
```

**This is the only record kind a browser ever follows.** Deleting one takes that
hostname down; the others are read by machines and never by a visitor.

The exact target is shown on the console before you authorize, and it is part of
the SHA-256 you approve — so it cannot change between the screen you read and the
write that happens.

**In a zone you own, this record is DNS-only.** MirrorStack does not turn on your
provider's proxy in your zone. (Records inside MirrorStack's *own* zones are
proxied; that is a different zone, not yours.)

Be precise about where that is decided, though: it is chosen when the plan is
built, in the private half. This service refuses a proxied *certificate* record
outright, because that one is a silent time bomb — but a proxied *routing*
record is legitimate inside a MirrorStack zone, so it is admitted here. If the
proxy state of your routing record matters to you, the thing to check is the
value on the consent screen, which is inside the digest.

### The console lane

Connecting the domain for your MirrorStack console registers up to four sibling
hostnames under it:

| Host | Serves |
|---|---|
| `account.<domain>` | the console itself |
| `api.<domain>` | the platform API for your organization |
| `apps.<domain>` | your applications |
| `cdn.<domain>` | static content |

Each contributes one routing record. The ownership proof above is shared across
all four — it is anchored at the domain they have in common, which is what lets
one record cover the whole set.

### The app-domain lane

One wildcard is all the routing you ever publish:

```
*.example.app   CNAME   <the MirrorStack endpoint>
```

It covers every app you deploy under that parent. **It is not all the DNS**: a
wildcard matches exactly one label, so `*.example.app` routes `blog.example.app`
and does *not* cover `_acme-challenge.blog.example.app`. Each app therefore still
owes one certificate record of its own, published when that app is created.

(A wildcard *custom hostname*, which would remove that requirement, is an
Enterprise-only feature on the provider account this runs against. So the
per-app record is a real requirement, not an implementation shortcut — and the
standing grant in the app lane exists precisely to satisfy it.)

---

## Record 3 — certificate validation

Two shapes, both read by a certificate authority, both under a reserved
underscore name that no browser resolves.

### 3a. The public certificate authority's challenge

```
_acme-challenge.<host>   TXT     <opaque token>            ← the usual form
_acme-challenge.<host>   CNAME   <id>.dcv.cloudflare.com   ← the delegated form
```

The provider mints the token; MirrorStack does not choose it. Only one of the two
forms is ever present at a given name — **a CNAME and a TXT cannot coexist at one
DNS name**, and publishing the wrong one does not merely fail to help, it blocks
the record issuance actually needs.

### 3b. The AWS certificate manager's challenge

```
_<token>.<host>   CNAME   <token>.acm-validations.aws
```

Present only for hostnames that terminate on AWS. AWS returns an ARN immediately
and populates this record seconds later, which is why a freshly connected
hostname is routinely "certificate requested, record not known yet" for the first
minutes of its life — and why the grant is held rather than spent once.

### Both shapes: **retained, and never proxied**

A certificate **renews** against these records, months after it was issued.
Deleting one does nothing visible today and takes TLS down at the next renewal.

Neither may be proxied. Cloudflare accepts `proxied: true` on these names with no
error and no warning, then flattens the CNAME to addresses — so a CA following it
finds IPs instead of a token, and issuance (or, much later, a silent renewal)
fails with every dashboard still green. A plan that would do this is refused
before anything is written; see
[`assertNoProxiedValidation`](../internal/dnsplan/purpose.go).

---

## What happens if a name is already in use

This is the case that would actually hurt: you are already serving something from
`account.example.com`, and MirrorStack wants that name too.

**We do not take it.** The publish is refused, the record already there is left
exactly as it is, and the refusal names the hostname and what it currently
answers with. Nothing partial is written.

To proceed, you delete that record yourself, in your own dashboard, and authorize
again — the only sequence in which the change was ever yours to make. A console
grant that has already closed needs a fresh authorization; a standing app-domain
grant picks the record up on its next pass, within about five minutes.

The one exception is a record that is **already ours** — same target — which we
will repair in place. That is what lets a connect that half-finished converge
rather than deadlock, and it can only ever change a record whose value we already
wrote.

See [`ErrNameInUse`](../internal/reconcile/reconcile.go) and
`TestPublishRefusesToReplaceARecordThatIsNotOurs`.

---

## Where the credential lives while it is held

Neither half of MirrorStack can use the credential alone.

| | api-platform (private) | dns-delegate-engine (this repository) |
|---|---|---|
| Holds the sealed refresh token | **yes**, as ciphertext | no — there is nowhere to persist it |
| Holds the key that opens it | no | **yes**, in a secret this service reads at runtime |
| Holds the OAuth client | no | **yes** |
| Holds a database | yes, every row | **none at all** |

A held grant is stored as an encrypted envelope on a MirrorStack row. The key
never leaves this service, and the envelope is bound to your organization, the
specific row, and the anchor — so it cannot be moved to another organization,
another domain, or a wider anchor. Any of those attempts fails to authenticate,
which is reported as `token_unreadable` and releases the grant rather than
widening it.

Cloudflare rotates the refresh token on every use, so each publish replaces the
stored envelope with a new one. If a publish fails *after* that rotation, this
service still returns the new sealed token so it can be persisted — reporting the
failure alone would leave MirrorStack holding a token the provider had already
replaced, and the grant would kill itself on the next pass having published
nothing. That is a bug this repository has already had; see the comment on
`PublishResponse` in [`internal/grant/types.go`](../internal/grant/types.go).

### Lifetimes

| Lane | Lifetime | Why |
|---|---|---|
| Console domain | held **24 hours**, then revoked | the record set is finite and known up front; the window covers records the provider has not minted yet, and is not shortened when the last one arrives |
| App domain | **standing**, extended each time it publishes | the record set is not known up front — the apps do not exist yet |

Both are revocable at your provider at any time, independently of MirrorStack.

---

## How the waiting works

MirrorStack re-derives the plan every five minutes and publishes only what is not
already there. It is the same plan, the same containment check, and the same
digest each time — a later pass cannot introduce a record you did not approve,
because the reviewed set is checked as a **lower bound**: the authoritative plan
may grow as a certificate authority answers, but it may never shrink or change
what you already saw.

When the window closes, the credential is revoked at the provider. The window is
not cut short when the last record lands — a console grant that published
everything on its first pass still holds the credential for the remaining
24 hours. Revoking at your provider ends it immediately if you would rather not
wait.
