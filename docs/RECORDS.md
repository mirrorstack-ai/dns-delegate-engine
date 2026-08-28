# Every record MirrorStack can write in your zone

The complete reference. If a record is not described here, no code path in this
service can produce it — the vocabulary is `CNAME` and `TXT` only, and every
record must sit at or under the anchor.

**The three lanes are listed separately**, because they do not write the same
records. An app domain never gets an AWS certificate record; a platform domain
never gets a wildcard; and a domain attached to a single app gets the tightest
anchor of the three. Read the one you are doing.

Each entry says **who writes it**, because that is changing. See
[`DESIGN.md`](DESIGN.md) for the shape being built; where the two disagree, this
file describes what runs **today**.

---

## The anchor

The anchor is the hostname you are connecting. It is the only bound on what a
delegated write can reach:

| connecting | anchor | reachable | never reachable |
|---|---|---|---|
| `example.com` | `example.com` | `example.com`, `account.example.com`, `_acme-challenge.api.example.com` | anything not ending `.example.com` |
| `shop.example.com` | `shop.example.com` | `shop.example.com` and below | `example.com`, `www.example.com`, `mail.example.com` |
| `example.net` | `example.net` | `*.example.net`, `_acme-challenge.blog.example.net` | anything outside `example.net` |
| `example.org` on one app | `example.org` | `example.org` only | `www.example.org`, and everything else in that zone |

The suffix is matched with a leading dot, so `evilexample.com` is not under
`example.com`. A wildcard `*.<anchor>` is under it and is allowed.

🔴 **Today the anchor is chosen by MirrorStack's private half, and the record
that is supposed to prove it is one we write ourselves.** That is the defect
[`DESIGN.md`](DESIGN.md) exists to fix: the proof becomes yours to publish, and
is re-checked on every pass.

---

## Lane 1 · an org platform domain

Your MirrorStack console on a hostname you own. Connecting `example.com`
registers up to four sibling hosts, and this is everything that lands:

| record | type | for | count |
|---|---|---|---|
| `_mirrorstack-challenge.example.com` | TXT | ownership | **one**, shared by all four hosts |
| `account.example.com` | CNAME | routing | one per host |
| `api.example.com` | CNAME | routing | ” |
| `apps.example.com` | CNAME | routing | ” |
| `cdn.example.com` | CNAME | routing | ” |
| `_<token>.account.example.com` | CNAME | AWS certificate | one per host that owns one |
| `_<token>.api.example.com` | CNAME | AWS certificate | ” |
| `_<token>.apps.example.com` | CNAME | AWS certificate | ” |
| `_acme-challenge.<host>` | TXT | certificate | one per host |
| `_cf-custom-hostname.<host>` | TXT | serving | one per host, when asked for |

Three things that table is saying quietly:

- **`cdn` has no AWS certificate row, and that is not an omission.** A content
  host is terminated before it ever reaches AWS, so it owns no certificate there
  and is owed no validation record. The other three do.
- **There is one ownership proof, not four.** It is anchored at the domain all
  four hosts have in common, which is what lets a single record cover the set.
- **The credential is held 24 hours**, because this record set is finite and
  known up front. See [lifetimes](#lifetimes).

---

## Lane 2 · an org app domain

One parent the org delegates once, under which **every app is auto-routed** at
`<app-slug>.example.net`. Nobody picks those hostnames per app — the slug
decides them and the single wildcard routes them all. Connecting `example.net`
with an app whose slug is `blog`:

| record | type | for | count |
|---|---|---|---|
| `*.example.net` | CNAME | routing | **one, ever** |
| `_mirrorstack-challenge.example.net` | TXT | ownership | one |
| `_acme-challenge.blog.example.net` | TXT | certificate | **one per app** |
| `_cf-custom-hostname.blog.example.net` | TXT | serving | one per app, when asked for |

- **No AWS certificate records on this lane, at all.** An app custom domain is a
  pure Cloudflare-for-SaaS hostname: it stays DNS-only and hands the request
  straight to MirrorStack's own zone, never reaching AWS from your edge. So the
  `_<token>.<host>` → `acm-validations.aws` row above simply has no counterpart
  here.
- **One wildcard is all the routing you ever publish — but it is not all the
  DNS.** `*.example.net` matches exactly one label, so it covers the auto-routed
  `blog.example.net` and never `_acme-challenge.blog.example.net`. Each app still
  owes certificate records of its own. A wildcard *custom hostname*, which
  would remove that, is Enterprise-only on the account this runs against. It is a
  real requirement, not a shortcut.
- **The credential is standing**, because the records it exists to write are for
  apps that do not exist yet, and its expiry slides forward each time it
  publishes. That is the trade to think hardest about on this repository.

---

## Lane 3 · a domain on a single app

An arbitrary domain bound to **one app** — `example.org` — not under any org
parent, and available to a **personal app** with no organization at all.

Authorized the same way as the other two, and with the tightest anchor of the
three: the anchor **is** the hostname, so nothing is derived beneath it and
nothing beside it in that zone is reachable.

| record | type | for | count |
|---|---|---|---|
| `_mirrorstack-challenge.example.org` | TXT | ownership | one |
| `example.org` | CNAME | routing | one |
| `_acme-challenge.example.org` | TXT | certificate | one, re-minted at renewal |
| `_cf-custom-hostname.example.org` | TXT | serving | one, when asked for |

- **No AWS certificate record**, for the same reason as lane 2: it is a
  Cloudflare-for-SaaS hostname that never reaches AWS from your edge.
- **The identity is the app and its owner**, which may be a person rather than an
  org. That is why this lane cannot be folded into lane 2.
- **The credential is held 24 hours, exactly as lane 1**, because this record set
  is closed too. It is also the fastest of the three to finish, having no AWS leg
  to wait on.

> **Not migrated yet.** Today this lane runs on an older path in MirrorStack's
> private half, where you paste a Cloudflare API token — no anchor, no ownership
> proof, no digest, and nothing in this repository bounds it. The table above is
> what it becomes; see [`DESIGN.md`](DESIGN.md).

---

## What each kind of record does

Identical in both lanes, so described once.

### ownership · `_mirrorstack-challenge.<anchor>` TXT

Proves the domain is yours. Everything downstream is gated on it: no custom
hostname is created until a public lookup returns the token, and no certificate
record can exist before a custom hostname does.

**Written by** MirrorStack today; **by you, in the target design** — which also
makes it a stop control: delete it and every write from this service stops.

**Retained.** Deleting it does nothing today; a later re-check fails.

### routing · `<host>` or `*.<domain>` CNAME

**The only record kind a browser ever follows.** Deleting one takes that hostname
down; everything else here is read by machines. The target is shown before you
authorize and is inside the digest you approve.

**In a zone you own these are DNS-only.** MirrorStack does not enable your
provider's proxy in your zone. Records inside MirrorStack's own zones are proxied
— a different zone, not yours — and that decision is made in the private half, so
read this as a description of what we do rather than a bound this repository
enforces today.

### certificate · read by a certificate authority

```
_<token>.<host>          CNAME   <token>.acm-validations.aws   ← AWS, platform lane only
_acme-challenge.<host>   TXT     <the DV token>                ← Cloudflare, both lanes
_acme-challenge.<host>   CNAME   <uuid>.dcv.cloudflare.com     ← delegated form, OFF in production
```

**Written by** this service, relaying bytes verbatim from AWS and Cloudflare. It
derives *that* a proof must exist; neither half chooses the token.

Only ever one form at `_acme-challenge`. A CNAME and a TXT cannot coexist at one
name, and publishing the wrong one does not merely fail to help — it blocks the
record issuance needs, silently.

**Retained, and never proxied.** A certificate **renews** against these months
later. Cloudflare accepts `proxied: true` on them with no error and then answers
with addresses instead of the token, so issuance — or a much later renewal —
fails with every dashboard still green.

### serving · `_cf-custom-hostname.<host>` TXT

🔴 **A second, separate proof, and not a certificate record.**

Cloudflare returns it when it cannot confirm from the routing record alone that
the zone may serve the name, and **withholds routing until the TXT exists**.
Missing it produces a **526 while the certificate status reads active** — the
hardest shape of this failure to diagnose, because DNS, the certificate and the
console all read healthy.

| | reads it | missing → |
|---|---|---|
| `_acme-challenge` | a certificate authority | renewal fails months later, silently |
| `_cf-custom-hostname` | the edge, before it will route | **526 now**, certificate healthy |

Its wait differs too: Cloudflare mints this when the custom hostname is
**created**, and mints the DV challenge after that host's routing record
resolves. Describing them with one word names the wrong blocker.

**Written by** this service, verbatim from Cloudflare. **Retained.**

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
sealed token so it can be persisted — reporting only the failure would leave the
private half holding a token the provider had already replaced.

🔴 **One caveat on that table, stated because it is currently true.** The key and
the OAuth client are read from two secrets that the private half's account role
*also* still holds read access to, left from the pre-cutover in-process path. No
code uses it — the delegated path runs entirely here — but the grant exists, so
"ciphertext it holds no key for" is a property of the code and not yet of the
permissions. Removing those grants is the outstanding half of the cutover.

### Lifetimes

| | 1 · org platform | 2 · org app domain | 3 · each app domain |
|---|---|---|---|
| held for | **24 hours** | **standing** | **24 hours** |
| ends when | the window closes — **not** when the last record lands | you revoke, or stop deploying for long enough | the window closes |
| why | the record set is closed and knowable up front | the records it exists to write are for apps that **do not exist yet** | the record set is closed, and smaller than lane 1 |

All three are revocable at your provider at any time, independently of
MirrorStack, and all three stop within one tick if you delete the ownership
proof.

🔴 **Renewal is not covered by a 24-hour window.** Cloudflare re-mints the DV
token under the same name when a certificate renews, months later — the reported
set stays authoritative per name, so a fresh value replaces the old one rather
than sitting beside it. By then lanes 1 and 3 hold no credential, so that write
needs a fresh authorization or a manual record. The permanent fix is the
delegated form of `_acme-challenge` — a CNAME pointing at Cloudflare, which
answers every future renewal without anyone writing anything. It is built and
switched off; see record form 3 above.
