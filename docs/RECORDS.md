# Every record MirrorStack can write in your zone

The complete reference for the intent surface: if a record is not described
here, nothing on that surface can produce it.

Two bounds hold on **both** surfaces, enforced in `internal/dnsplan` with no
path around either — the vocabulary is `CNAME` and `TXT` only, and every record
must sit at or under the anchor. But on the legacy `publish(records)` surface
the name and the value *inside* those bounds are the caller's to choose, so that
surface can put a record in your zone that this file does not list. That is the
defect the rebuild exists to close, and it is why every entry below says which
surface it is describing.

**The three lanes are listed separately**, because they do not write the same
records. An app domain never gets an AWS certificate record; a platform domain
never gets a wildcard; and a domain attached to a single app gets the tightest
anchor of the three. Read the one you are doing.

Each entry says **who writes it**, and today there are two surfaces to say it
about. The intent surface [`DESIGN.md`](DESIGN.md) describes is deployed and
running. The legacy `publish(records)` surface it replaces is **still routed in
the same binary, behind the same OAuth client**, and MirrorStack's private half
still calls it. Where a row differs between the two, both are given — and where
they differ, the weaker one is what bounds the deployment until the legacy
action is deleted.

---

## The anchor

The anchor is the hostname you are connecting. On the intent surface it is the
only bound on what a delegated write can reach. On the legacy surface it is a
field on the request, which is a different thing entirely — read to the end of
this section before relying on the table:

| connecting | anchor | reachable | never reachable |
|---|---|---|---|
| `example.com` | `example.com` | `example.com`, `account.example.com`, `_acme-challenge.api.example.com` | anything not ending `.example.com` |
| `shop.example.com` | `shop.example.com` | `shop.example.com` and below | `example.com`, `www.example.com`, `mail.example.com` |
| `example.net` | `example.net` | `*.example.net`, `_acme-challenge.blog.example.net` | anything outside `example.net` |
| `example.org` on one app | `example.org` | `example.org` only | `www.example.org`, and everything else in that zone |

The suffix is matched with a leading dot, so `evilexample.com` is not under
`example.com`. A wildcard `*.<anchor>` is under it and is allowed.

Who chooses the anchor, and what proves it, is the one thing that differs most
between the two surfaces:

🔴 **On the legacy `publish(records)` surface the anchor is a field on the
publish request.** It is not derived from anything, and on the authorization-code
path nothing binds it to anything you proved — so the table above does not
describe that surface. Connecting `shop.example.com` yields a credential your
provider scoped to the whole `example.com` zone, and a publish naming
`example.com` as its anchor reaches `www.example.com` with every check in this
repository passing.

The ownership TXT does not close that either, because on this surface **we write
it ourselves**, and the gate on connecting a hostname is a public lookup for that
same record — so the proof is satisfied by our own write and proves nothing.
That surface is still routed.

✅ **On the intent surface the proof is yours.** The anchor comes out of a
registration this service sealed and the caller cannot edit; the TXT value is
`HMAC(K, lane‖identity‖anchor)`, recomputed here rather than accepted from
anyone; and it is re-resolved in public DNS before `authorize` will mint a
consent URL and again on every later pass. That is what makes the anchor a bound
you set rather than one we assert.

Until the legacy action is deleted, the first of those is what your zone is
actually bounded by — which is to say, by your provider's zone scope and not by
an anchor at all. See [`DESIGN.md`](DESIGN.md)'s status block.

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
| `_cf-custom-hostname.<host>` | TXT | serving | one per host, when asked for — 🔴 **not produced by this build** |

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
| `_acme-challenge.blog.example.net` | CNAME | certificate | **one per app**, permanent |
| `_cf-custom-hostname.blog.example.net` | TXT | serving | one per app, when asked for — 🔴 **not produced by this build** |

- **The per-app rows appear when that app is deployed**, not when you connect
  the parent. If the parent holds a live authorization they are written for you;
  if not, they are handed back for you to add by hand. Either way the wildcard
  already routes the app, so what is outstanding is only its certificate.
  🔴 **On this build that hand-back is one record, not the two above**, because
  the serving proof is not produced — see [serving](#serving--_cf-custom-hostnamehost-txt).
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
- 🔴 **On the intent surface this lane cannot be authorized on this build at
  all.** It is the one lane that requires this service's own consent page to have
  been acknowledged — a wildcard is the one grant whose scope you cannot
  enumerate for yourself — and nothing in the deployed binary mints an
  acknowledgement. So `authorize` refuses it every time. What runs today for this
  lane is the legacy record-list path. [`DESIGN.md`](DESIGN.md) §4 has the
  reasoning and why refusing is the safe end of the failure.

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
| `_cf-custom-hostname.example.org` | TXT | serving | one, when asked for — 🔴 **not produced by this build** |

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

Proves the domain is yours. Everything downstream is gated on it: no custom
hostname is created until a public lookup returns the token, and no certificate
record can exist before a custom hostname does.

**Written by you on the intent surface**, and **by MirrorStack on the legacy
one.** That difference is the whole point of the rebuild: a proof we write
ourselves proves nothing.

**On the intent surface it is a stop control.** Delete it and every write from
this service stops on the first pass after the deletion is visible in public DNS
— your record's TTL, then up to one interval plus the jitter, which is five
minutes and one more with the numbers this build declares. Nothing has to reach
MirrorStack for that to take effect, and nobody has to agree to it.

The limit, stated because it is the interesting case: **a pass that cannot reach
a resolver at all does not stop.** It publishes and records a warning. A
nameserver failure must not be read as you saying no — otherwise a blip on our
side would release a live credential and strand a working domain — so the stop
is on an answer, never on the absence of one.

**On the legacy surface, deleting it does nothing.** Nothing re-checks it there;
that is defect two in [`DESIGN.md`](DESIGN.md) §1.

**Retained on both.** Nothing in this service deletes a record, this one
included.

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
you just connected, and the uuid is fixed configuration for MirrorStack's zone.

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

🔴 **AND NOT PRODUCED BY THIS BUILD, ON ANY LANE.** The relay that would fetch
it exists in `internal/relay` and nothing wires it: it needs MirrorStack's own
Cloudflare API token and the id of the SaaS zone the custom hostname sits in,
and that zone differs between the org lane and the app lane while the field that
would hold it does not. Both have to be settled before it can be filled in.

Two consequences worth being blunt about. **Every lane can therefore land in the
526-with-a-healthy-certificate state above** — the row that makes this the
hardest failure here to diagnose is the row that is missing. And a
`BindAppToOrgAppDomain` that falls back to the manual path hands you **one**
record where lane 2's table lists two; the `_acme-challenge` pointer is the one
you get.

It is left unwired rather than approximated because an absent row is visibly
incomplete and an invented one is confidently wrong. Nothing else in a plan is
affected: everything derivable is still published.

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
rather than widening it. The bindings differ by surface:

| surface | the sealed grant is bound to |
|---|---|
| legacy `publish(records)` | the organization, the row, the anchor |
| intent | **the lane**, the identity — an org id on lanes 1 and 2, an **app** id on lane 3 — and the anchor |

🔴 **The lane is the binding the legacy form had no way to express.** One org can
connect the same domain on two lanes. Those are two separate consents, two
separate ownership proofs and two separate grants — and without the lane inside
the seal, a grant obtained for the wildcard lane would open in the platform
lane's row and write there.

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

Those grants are being removed, along with the rollback to the legacy path that
depended on them. Once that deploys, no private MirrorStack function can read
either secret, and the sentence above is true of the IAM as well.

### Lifetimes

| | 1 · org platform | 2 · org app domain | 3 · each app domain |
|---|---|---|---|
| held for | **24 hours** | **standing** | **24 hours** |
| ends when | the window closes — **not** when the last record lands | you revoke, or stop deploying for long enough | the window closes |
| why | the record set is closed and knowable up front | the records it exists to write are for apps that **do not exist yet** | the record set is closed, and smaller than lane 1 |

All three are revocable at your provider at any time, independently of
MirrorStack. And on the intent surface all three stop on the first pass after a
deleted ownership proof becomes visible in public DNS — your record's TTL, then
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
