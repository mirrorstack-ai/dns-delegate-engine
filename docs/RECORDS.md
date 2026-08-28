# Every record MirrorStack can write in your zone

The complete reference. If a record is not described here, no code path in this
service can produce it — the vocabulary is `CNAME` and `TXT` only, and every
record must sit at or under the anchor.

Each entry says **who writes it**, because that is changing. See
[`DESIGN.md`](DESIGN.md) for the shape being built; where the two disagree, this
file describes what runs **today**.

---

## The anchor

The anchor is the hostname the customer is connecting. It is the only bound on
what a delegated write can reach:

| connecting | anchor | reachable | never reachable |
|---|---|---|---|
| `example.com` | `example.com` | `example.com`, `account.example.com`, `_acme-challenge.api.example.com` | anything not ending `.example.com` |
| `shop.example.com` | `shop.example.com` | `shop.example.com` and below | `example.com`, `www.example.com`, `mail.example.com` |
| `example.app` | `example.app` | `*.example.app`, `_acme-challenge.blog.example.app` | anything outside `example.app` |

The suffix is matched with a leading dot, so `evilexample.com` is not under
`example.com`. A wildcard `*.<anchor>` is under it and is allowed.

🔴 **Today the anchor is chosen by MirrorStack's private half, and the record
that is supposed to prove it is one we write ourselves.** That is the defect
[`DESIGN.md`](DESIGN.md) exists to fix: the proof becomes the customer's to
publish, and is re-checked on every pass.

---

## 1 — ownership · `_mirrorstack-challenge.<anchor>` TXT

One per connected domain, at the anchor itself. Everything downstream is gated on
it: no custom hostname is created until a public lookup returns the token, and no
certificate record can exist before a custom hostname does.

**Written by:** MirrorStack today. **The customer, in the target design** — which
also makes it a stop control: delete it and every write from this service stops.

**Retained.** Deleting it does nothing today; a later re-check fails.

---

## 2 — routing · `<host>` or `*.<domain>` CNAME

**The only record kind a browser ever follows.** Deleting one takes that hostname
down; everything else here is read by machines.

| lane | records |
|---|---|
| console | one per sibling host — `account.` `api.` `apps.` `cdn.` |
| app domain | one wildcard, `*.<domain>` |
| app host | the hostname itself |

The target is shown before you authorize and is inside the digest you approve.

**In a zone you own these are DNS-only.** MirrorStack does not enable your
provider's proxy in your zone. Records inside MirrorStack's own zones are
proxied — a different zone, not yours — and that decision is made in the private
half, so read this as a description of what we do rather than a bound this
repository enforces today.

### The wildcard is not all the DNS

`*.example.app` matches exactly one label. It routes `blog.example.app` and does
**not** cover `_acme-challenge.blog.example.app`, so each app still owes a
certificate record of its own. A wildcard *custom hostname*, which would remove
that requirement, is Enterprise-only on the account this runs against. It is a
real requirement, not an implementation shortcut — and it is why the app-domain
grant is standing rather than 24 hours.

---

## 3 — certificate · read by a certificate authority

Two shapes, both under a reserved underscore name no browser resolves.

```
_<token>.<host>          CNAME   <token>.acm-validations.aws   ← AWS
_acme-challenge.<host>   TXT     <the DV token>                ← Cloudflare, usual form
_acme-challenge.<host>   CNAME   <uuid>.dcv.cloudflare.com     ← delegated form, OFF in production
```

**Written by:** this service, relaying bytes verbatim from AWS and Cloudflare.
It derives *that* a proof must exist; neither half chooses the token.

Only ever one form at `_acme-challenge`. A CNAME and a TXT cannot coexist at one
name, and publishing the wrong one does not merely fail to help — it blocks the
record issuance needs, silently.

**Retained, and never proxied.** A certificate **renews** against these months
later. Cloudflare accepts `proxied: true` on them with no error and then answers
with addresses instead of the token, so issuance — or a much later renewal —
fails with every dashboard still green.

---

## 4 — serving · `_cf-custom-hostname.<host>` TXT

🔴 **A second, separate proof, and not a certificate record.**

Cloudflare returns `ownership_verification` when it cannot confirm from the
routing record alone that the zone may serve the name, and **withholds routing
until the TXT exists**. Missing it produces a **526 while the certificate status
reads active** — the hardest shape of this failure to diagnose, because DNS, the
certificate and the console all read healthy.

| | reads it | missing → |
|---|---|---|
| `_acme-challenge` | a certificate authority | renewal fails months later, silently |
| `_cf-custom-hostname` | the edge, before it will route | **526 now**, certificate healthy |

Its wait is also different: Cloudflare mints this when the custom hostname is
**created** (after the shared proof resolves); it mints the DV challenge after
that host's own routing record resolves. Describing them with one word names the
wrong blocker.

**Written by:** this service, verbatim from Cloudflare. **Retained.**

---

## When a name is already in use

You are already serving something from `account.example.com`, and MirrorStack
wants that name.

**We do not take it.** The publish is refused, the record is left exactly as it
is, and the refusal names the hostname and what it currently answers with.
Nothing partial is written. You delete that record yourself and authorize again —
the only sequence in which the change was ever yours to make.

The one exception is a record that is **already ours**, same target, which we
repair in place. That is what lets a half-finished connect converge.

Two honest limits: the check compares records of the **same type**, so an `A`
record where the plan wants a `CNAME` is left for your provider to reject rather
than caught here; and TXT records always **add** beside yours, never replacing
them — which is why a TXT can never destroy an existing one, and also why
containment cannot bound a TXT's value.

---

## Where the credential lives

| | private half | this service |
|---|---|---|
| the sealed refresh token | stored, as ciphertext | issued |
| the key that opens it | — | ✅ |
| the OAuth client | — | ✅ |
| a database | every row | **none** |

The envelope is bound to the organization, the row and the anchor, so it cannot
be moved to another organization, another domain, or a wider anchor. Any of those
fails to authenticate, which releases the grant rather than widening it.

Cloudflare rotates the refresh token on every use, so each publish replaces the
stored envelope. A publish that fails *after* that rotation still returns the new
sealed token, so it can be persisted — reporting only the failure would leave the
private half holding a token the provider had already replaced.

🔴 **One caveat on the table above, stated because it is currently true.** The
key and the OAuth client are read from two secrets that the private half's
account role *also* still holds read access to, left from the pre-cutover
in-process path. No code uses it — the delegated path runs entirely here — but the
grant exists, so "ciphertext it holds no key for" is a property of the code and
not yet of the permissions. Removing those grants is the outstanding half of the
cutover.

### Lifetimes

| lane | lifetime |
|---|---|
| console domain | held **24 hours**, then revoked; not shortened when the last record lands |
| app domain | **standing**, extended each time it publishes |

Both are revocable at your provider at any time, independently of MirrorStack.
