# Every record MirrorStack can write in your zone

The complete reference: if a record is not described here, nothing this service
can be asked to do produces it.

Two bounds are enforced in `internal/dnsplan` with no path around either — the
vocabulary is `CNAME` and `TXT` only, and every record must sit at or under the
anchor. What is *inside* those bounds is derived here rather than chosen by the
caller, which is why this file can be a complete list rather than a description
of a shape. The record-list surface that could put an unlisted record in your
zone is deleted; [`DESIGN.md`](DESIGN.md) §1 is what it was.

**The three lanes are listed separately**, because they do not write the same
records. An app domain never gets an AWS certificate record; a platform domain
never gets a wildcard; and a domain attached to a single app gets the tightest
anchor of the three. Read the one you are doing.

Each entry says **who writes it** — you, or this service under your grant.

---

## The anchor

The anchor is the hostname you are connecting, and it is the only bound on what
a delegated write can reach:

| connecting | anchor | reachable | never reachable |
|---|---|---|---|
| `example.com` | `example.com` | `example.com`, `account.example.com`, `_acme-challenge.api.example.com` | anything not ending `.example.com` |
| `shop.example.com` | `shop.example.com` | `shop.example.com` and below | `example.com`, `www.example.com`, `mail.example.com` |
| `example.net` | `example.net` | `*.example.net`, `_acme-challenge.blog.example.net` | anything outside `example.net` |
| `example.org` on one app | `example.org` | `example.org` only | `www.example.org`, and everything else in that zone |

The suffix is matched with a leading dot, so `evilexample.com` is not under
`example.com`. A wildcard `*.<anchor>` is under it and is allowed.

Who chooses the anchor, and what proves it, is the whole of why the table above
can be relied on:

✅ **The proof is yours.** The anchor comes out of a registration this service
sealed and the caller cannot edit; the TXT value is
`HMAC(K, lane‖identity‖anchor)`, recomputed here rather than accepted from
anyone; and it is re-resolved in public DNS before `authorize` will mint a
consent URL and again on every later pass. That is what makes the anchor a bound
you set rather than one we assert.

The surface this replaced took the anchor as a **field on the publish request**,
bound to nothing you had proved, so its reach was your provider's zone scope
rather than a hostname. It is deleted — see [`DESIGN.md`](DESIGN.md) §1 for what
it was and why.

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
| `_acme-challenge.<host>` | CNAME | certificate | one per host, **permanent** |
| `_cf-custom-hostname.<host>` | TXT | serving | one per host, when asked for |
| `<token>._domainkey.example.com` | CNAME | mail (DKIM) | **three**, shared by all four hosts |

Four things that table is saying quietly:

- **`cdn` has no AWS certificate row, and that is not an omission.** A content
  host is terminated before it ever reaches AWS, so it owns no certificate there
  and is owed no validation record. The other three do.
- **There is one ownership proof, not four.** It is anchored at the domain all
  four hosts have in common, which is what lets a single record cover the set.
- **There are three DKIM rows and they are anchored, not per host.** One sending
  identity belongs to the domain you registered, and invitations go out as
  `noreply@example.com` — not as `noreply@account.example.com`, which reads as a
  machine artifact and only aligns under relaxed DMARC. AWS issues three keys so
  it can rotate one out without you touching DNS again. Leave them DNS-only: a
  proxied DKIM CNAME is flattened at the edge and every signature fails while the
  record still looks correct.
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
| `_acme-challenge.blog.example.net` | CNAME | certificate | **one per app**, permanent |
| `_cf-custom-hostname.blog.example.net` | TXT | serving | one per app, when asked for |

- **The per-app rows appear when that app is deployed**, not when you connect
  the parent. If the parent holds a live authorization they are written for you;
  if not, they are handed back for you to add by hand. Either way the wildcard
  already routes the app, so what is outstanding is only its certificate. It is
  both records above wherever this deployment reads the serving proof for the
  lane, and only the `_acme-challenge` pointer where it does not — see
  [serving](#serving--_cf-custom-hostnamehost-txt).
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
- 🔴 **This lane cannot be authorized on this build at all.** It is the one lane
  that requires this service's own consent page to have been acknowledged — a
  wildcard is the one grant whose scope you cannot enumerate for yourself — and
  no deployment routes that page, so `authorize` refuses it every time. Nothing
  weaker sits behind the refusal: the record-list path that used to run this lane
  is deleted, so the wildcard is added by hand until the page is served.
  [`DESIGN.md`](DESIGN.md) §4 has the reasoning and why refusing is the safe end
  of the failure.

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
| `_acme-challenge.example.org` | CNAME | certificate | one, **permanent** |
| `_cf-custom-hostname.example.org` | TXT | serving | one, when asked for |

- **No AWS certificate record**, for the same reason as lane 2: it is a
  Cloudflare-for-SaaS hostname that never reaches AWS from your edge.
- **The identity is the app and its owner**, which may be a person rather than an
  org. That is why this lane cannot be folded into lane 2.
- **The credential is held 24 hours, exactly as lane 1**, because this record set
  is closed too. It is also the fastest of the three to finish, having no AWS leg
  to wait on.

> **Half migrated.** The engine side has shipped: `AddAppDomain` is a deployed
> wire action, it registers this lane exactly as the table above describes, and
> it feeds the same lifecycle — the same sealed registration, the same ownership
> proof, the same refusals — that lanes 1 and 2 use. What has not moved is the
> caller. MirrorStack's private half still runs this lane on the older path,
> where you paste a Cloudflare API token: no anchor, no ownership proof, no
> digest, and nothing in this repository bounds it. So the table above is what
> you get once that switch is thrown, and the pasted token is what you get
> today. See [`DESIGN.md`](DESIGN.md).

---

## What each kind of record does

Identical in both lanes, so described once.

### ownership · `_mirrorstack-challenge.<anchor>` TXT

Marks the domain as registered with MirrorStack.

🔴 **It is not a proof, and it does not gate anything.** It was both, and the
history matters because the name still says `challenge`: the value is a MAC over
(lane, identity, anchor), it used to be yours to publish, and `Authorize`,
`Complete` and `Advance` all refused without it.

**Written by MirrorStack.** Published with the rest of the plan, and republished
on a later pass if you delete it.

🔴 **It is NOT a stop control.** Deleting it stops nothing — publication
continues whether or not it resolves. To stop MirrorStack writing to your zone,
revoke the credential at your DNS provider; that is the only control that works,
it takes effect immediately, and it does not need us to cooperate.

Both halves changed together, deliberately. A self-published marker combined
with proof-based authorization would be the original defect — our own write
satisfying our own check — so the gate went when the authorship did. Restoring
either without the other is the one change this record must never take.

**Retained.** Nothing in this service deletes a record, this one included.

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
_<token>.<host>          CNAME   <token>.acm-validations.aws            ← AWS, platform lane only
_acme-challenge.<host>   CNAME   <host>.<uuid>.dcv.cloudflare.com       ← Cloudflare, all lanes
```

**The `_acme-challenge` record carries no token.** It is a *pointer*, and both
halves of it are known before anything is asked of anyone: the hostname is what
you just connected, and the uuid identifies the MirrorStack zone your hostname is
served from. That uuid is **read from Cloudflare**, per zone, rather than
configured — `capabilities` names which lane got it from where.

The token still exists — it lives at the far end, in Cloudflare's own zone,
placed by Cloudflare. A certificate authority looking up
`_acme-challenge.example.com` follows the pointer and reads the token there.

Two things follow, and they are the reason this form is used:

- **Nothing to wait for.** It is publishable in the first pass, before a
  certificate has been requested or a custom hostname created.
- **Nothing to republish, ever.** Cloudflare mints, rotates and re-mints tokens
  behind the pointer for every future renewal. Your zone never changes again.

The AWS record above is different: its value is a token AWS chooses, so it is
relayed verbatim and arrives only once AWS has answered.

**Retained, and never proxied.** Deleting the pointer takes TLS down at the next
renewal — silently, months later. And Cloudflare accepts `proxied: true` on these
names with no error, then answers with addresses instead of following the
delegation, so issuance or a much later renewal fails with every dashboard still
green.

### serving · `_cf-custom-hostname.<host>` TXT

🔴 **A second, separate proof, and not a certificate record.**

Cloudflare returns it when it cannot confirm from the routing record alone that
the zone may serve the name, and **withholds routing until the TXT exists**.
Missing it produces a **526 while the certificate status reads active** — the
hardest shape of this failure to diagnose, because DNS, the certificate and the
console all read healthy.

| | reads it | missing → |
|---|---|---|
| `_acme-challenge` | a certificate authority, via the delegation | renewal fails months later, silently |
| `_cf-custom-hostname` | the edge, before it will route | **526 now**, certificate healthy |

Its wait differs too: Cloudflare mints this when the custom hostname is
**created**, and mints the DV challenge after that host's routing record
resolves. Describing them with one word names the wrong blocker.

**Written by** this service, verbatim from Cloudflare. **Retained.**

🔴 **AND IT IS READ PER LANE, FROM A DIFFERENT MIRRORSTACK ZONE.** The custom
hostname is ours, not yours: lane 1's lives in MirrorStack's org zone and lanes 2
and 3 in its app/SaaS zone, and the **lane** picks between them — never your
hostname, which would let a name you chose select which of our zones we
authenticate against.

Two things follow, and both are things you can check. A deployment reading the
wrong zone finds no custom hostname for your host, which is indistinguishable
from a proof Cloudflare has not minted yet — so `capabilities` names the zone id
for each lane, and a lane naming none will not produce this record at all. And
where a lane is unconfigured, a `BindAppToOrgAppDomain` falling back to the
manual path hands you **one** record where lane 2's table lists two; the
`_acme-challenge` pointer is the one you get.

Nothing else in a plan depends on it: an unreadable edge is a warning on the
pass, never a refusal, and everything derivable is still published. The value is
never approximated — an absent row is visibly incomplete and an invented one is
confidently wrong.

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

🔴 **And that repair can turn your proxy off.** "Already ours" is matched on the
record's **value** alone, so a CNAME carrying our target with *your* proxy
switched on is ours, and the repair rewrites it DNS-only. It is the one place in
this service that overwrites a deliberate choice you made: "we only ever add" is
true of names, and it is not true of this flag.

It is also required for delegation to work at all. A proxied record in **your**
zone is flattened at **your** edge — the name answers with addresses instead of
following the delegation, so the request never reaches MirrorStack's zone, and
issuance, or a renewal months later, fails with every dashboard on both sides
still green. Cloudflare accepts `proxied: true` on these names without an error,
which is what makes leaving it a silent failure rather than a rejected write.
Nothing this service derives is ever proxied (`internal/derive` ships that as a
one-line rule with no path around it), and the reconciler compares the flag in
**both** directions rather than assuming grey is always right, so it repairs
toward what the plan says rather than toward one preferred state.

If you need one of these names proxied at your own edge, delegation cannot give
you that on either path — the flattening is your edge's behaviour, not ours.

Two honest limits: the check compares records of the **same type**, so an `A`
record where the plan wants a `CNAME` is left for your provider to reject rather
than caught here; and TXT records always **add** beside yours, never replacing
them — which is why a TXT can never destroy an existing one, and also why
containment cannot bound a TXT's value.

---

## Which zone we write into

The zone is located by asking your provider which zone holds **the first record
in the plan**, not by asking which zone holds the anchor. The most specific
authorized zone wins.

For almost every customer those are the same zone and nothing about this is
visible. The case where they are not: you run `account.example.com` as its
**own** delegated zone, separate from `example.com`. Lane 1's plan begins with a
record under `account.`, so that zone is the one selected — and the writes for
`api.`, `apps.` and `cdn.`, which live in the other zone, are then attempted
where your credential is not authoritative, and fail.

**That is a failure and not a compromise.** Nothing lands outside the anchor:
containment is checked when the plan is built and re-checked inside the
publisher, so the wrong zone means refused writes rather than writes in the
wrong place. But it is a confusing failure — the error names a record and a
provider response, not the split-zone setup that caused it — and it is worth
knowing before you connect a domain whose subdomains are delegated separately.

---

## Where the credential lives

| | private half | this service |
|---|---|---|
| the sealed refresh token | stored, as ciphertext | issued |
| the key that opens it | — | ✅ |
| the OAuth client | — | ✅ |
| a database | every row | **none** |

The envelope is bound, by the AEAD's associated data, to what identifies whose
grant it is — so it cannot be moved to another organization, another domain, or
a wider anchor. Any of those fails to authenticate, which releases the grant
rather than widening it. It is bound to **the lane**, the identity — an org id on
lanes 1 and 2, an **app** id on lane 3 — and the anchor.

🔴 **The lane is in the seal.** One org can connect the same domain on two
lanes. Those are two separate consents, two separate ownership proofs and two
separate grants — and without the lane, a grant obtained for the wildcard lane
would open in the platform lane's row and write there.

What the intent form does **not** distinguish is two registrations with the same
lane, identity and anchor: there is no row id in the seal, because this service
holds no rows and [`DESIGN.md`](DESIGN.md) §5 gives it no field to receive one.
Re-registering a domain you already registered on the same lane therefore
produces an envelope your existing grant opens. That is deliberate — it is what
lets a half-finished connect converge instead of stranding the credential — but
it is a binding to a domain rather than to an attempt, and it is better said
than implied.

Cloudflare rotates the refresh token on every use, so each publish replaces the
stored envelope. A publish that fails *after* that rotation still returns the new
sealed token so it can be persisted — reporting only the failure would leave the
private half holding a token the provider had already replaced.

**One caveat, stated because it was true until recently.** The key and the OAuth
client are read from two secrets that the private half's account role *also* held
read access to, left from the pre-cutover in-process path — duplicated onto it
rather than moved. No code used them, but a granted capability is
indistinguishable from a used one to anyone auditing from outside, so
"ciphertext it holds no key for" was a property of the code and not of the
permissions.

Those grants are being removed. Once that deploys, no private MirrorStack
function can read either secret, and the sentence above is true of the IAM as
well.

### Lifetimes

| | 1 · org platform | 2 · org app domain | 3 · each app domain |
|---|---|---|---|
| held for | **24 hours** | **standing** | **24 hours** |
| ends when | the window closes — **not** when the last record lands | you revoke, or stop deploying for long enough | the window closes |
| why | the record set is closed and knowable up front | the records it exists to write are for apps that **do not exist yet** | the record set is closed, and smaller than lane 1 |

All three are revocable at your provider at any time, independently of
MirrorStack. And all three stop on the first pass after a deleted ownership proof
becomes visible in public DNS — your record's TTL, then
up to one interval plus the jitter — with the one exception described under
[ownership](#ownership--_mirrorstack-challengeanchor-txt): a pass that cannot
reach a resolver publishes and warns rather than stopping.

**Renewal needs no credential at all.** Cloudflare's DCV tokens expire on a short
clock — 7 days for Let's Encrypt, 14 for Google Trust Services — so a form that
put the token *in your zone* would need republishing at every renewal, forever,
by a grant that no longer exists. The delegation pointer sidesteps that entirely:
the tokens rotate behind it, in Cloudflare's zone, and nothing in yours is
touched. A 24-hour window is therefore sufficient for a closed lane, and that is
why lanes 1 and 3 can have one.
