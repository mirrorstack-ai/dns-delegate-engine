# The intent-based API

The shape this service was rebuilt into: MirrorStack's private half names a
**domain and an intent**, and cannot name a DNS record at all. It is the whole
wire surface, which is what §1 is about.

> **Status: built, and not finished.** This file described a proposal until
> 2026-08-28 and describes the deployed surface now. Everything below is
> implemented and dispatched: the four intents, all seven lifecycle functions,
> `capabilities`, `health`, and both upstream relays. Record 7 appears on a lane
> once that deployment names the zone it reads and holds MirrorStack's own
> Cloudflare token; `capabilities` says, per lane, which zone that is. §6.
>
> Two parts do not, and each is marked where it belongs:
>
> - **Lane 2's consent page is served by no deployment.** The flow is built —
>   the page carries a challenge, posting it back mints the acknowledgement
>   `authorize` requires — but nothing routes that path, so the lane is still
>   refused every time. Nothing weaker sits behind that refusal any more, so the
>   lane is added by hand until the page is routed. What the acknowledgement does
>   and does not prove is §4.
> - **The rate floor in `internal/schedule` is declared and enforced nowhere.**
>   §8.
>
> ✅ **The record-list surface §1 is about is deleted.** `publish(records)`, the
> `authorize` that took a caller-supplied state, and the `capabilities` and
> `revoke` beside them are gone from the dispatcher, along with the package that
> implemented them. Nothing routes them, so the bound below is a property of the
> deployment rather than of one surface within it — which is the claim this
> document could not make while both were live.
>
> [`../README.md`](../README.md) opens with the same status, shorter, and then
> walks the code. [`RECORDS.md`](RECORDS.md) lists every record this service can
> write, per lane.

---

## 1 · Why the record list had to go

This service used to take `Publish(records)`. Every byte that reached your zone
came from that list. Anchor containment bounds a record's **name** to a suffix of
the anchor, and **nothing bounds its value**. So the private half could publish,
with every check here passing:

```
CNAME  account.example.com          →  attacker.example
TXT    _acme-challenge.example.com  →  a third party's ACME token
```

The first puts a session host inside your own domain in front of someone else's
origin. The second lets that third party obtain a publicly-trusted certificate
for your hostname — and the never-replace rule is CNAME-only, because TXT records
always *add*, and a certificate authority accepts any matching TXT among several
at one owner.

Reading this repository told you **where** we could write and nothing about
**what**. That is what the rebuild fixed.

There was a second defect, and it is the one everything else follows from: **the
anchor was not proven.** The ownership TXT sat inside the record set *we*
published, and the gate on creating a custom hostname was a public lookup for
that same record. The proof was satisfied by our own write.

So the change was not only "send an intent instead of a record list". It is:

> **The record that proves the anchor becomes one you publish, and it is
> re-checked on every pass.**

Without that, an intent API would still let a compromised private half aim this
service at any name inside a zone you authorized — your provider's consent screen
names the *zone*, never the subdomain — and it would claim a property it does not
have, which is worse than the surface it replaced.

---

## 2 · Which lane you are on

| | 1 · org platform domain | 2 · org app domain | 3 · each app domain |
|---|---|---|---|
| example | `example.com` | `example.net` | `example.org` |
| what it is | the org's console on its own hostname | a parent under which every app is **auto-routed** at `<app-slug>.example.net` | one arbitrary domain bound to **one app** |
| identity | the org | the org | **the app and its owner — which may be a person** |
| anchor | `example.com` | `example.net` | `example.org` |
| hosts | `account.` `api.` `apps.` `cdn.` | auto-routed, one per app | itself |
| grant | 24 hours | standing | 24 hours |

All three are authorized the same way — a provider grant scoped to one zone, held
by this service — and all three are bounded by a proof you published at the
anchor. There is no lane with a weaker path — that is the design, and it is why
they are listed together.

On this build two of the three are not yet reachable on those terms: lane 2 is
refused at `authorize` because nothing mints a consent acknowledgement (§4), and
lane 3 still runs on the caller's older pasted-token path (the migration note
below). Both refusals now end in the manual path rather than in a weaker one. The
design is what the table describes; the status block at the top of this document
is what runs.

Lane 3 is the one to read carefully. It is not "an app under the org's parent" —
it is a domain someone attaches to a single app, and it must work when there is
no organization at all. That is why it cannot be folded into lane 2, and why it
needs its own identity rather than an `orgId`. Its anchor is also the tightest of
the three: the anchor **is** the hostname, so nothing is derived beneath it and
nothing beside it in that zone is reachable.

> **Migration note.** Lanes 1 and 2 run through this service today. Lane 3 does
> not: it still uses an older path in the private half where a Cloudflare API
> token is pasted, with no anchor and no digest. Bringing it onto the design
> below is a migration, not a new feature, and it is the reason the third intent
> exists.

---

### Or none of it — the manual path

Every lane can be done by hand. You add the records in your own provider and
never grant MirrorStack anything. That path has no credential, so nothing in this
service writes on it — but the **list you are told to add comes from here all the
same**, through `describe`.

That is not a technicality, it is the point:

- **One derivation, two paths.** Today the console renders its list from one
  place in the private half and the delegated writer builds its own from another.
  Two implementations of the same question drift, and the loose one is the one
  that matters. After this, the records you are asked to add by hand are the same
  bytes we would have written — because they are produced by the same function.
- **A customer who grants nothing still gets this repository.** If you never
  authorize, no credential of yours exists anywhere in MirrorStack, and you can
  still read exactly what you will be asked to publish, and why each record is
  there, before you type any of it.
- **`describe` also reports what it observes** — present, absent, conflicting, or
  the wrong type — so "I added it and nothing happened" has an answer that does
  not require a support reply.

So the split is by capability rather than by path:

| | manual | delegated |
|---|---|---|
| who derives the records | this service | this service |
| who writes them | **you** | this service, under your grant |
| credential held | none, anywhere | one, here |
| what a failure looks like | a record reported absent | a refusal with a reason |

The delegated path is the manual path plus a credential and a writer. Nothing
else about it differs, which is what makes revoking safe: it does not break the
domain, it returns you to the path everyone starts on.

---

## 3 · What MirrorStack can ask for

These are the entry points, and there are no others on the deployment. Three of
them register a domain, and each takes a name and an identity and returns the
proof you must publish before anything else happens. The fourth runs later, per
app.

**The wire action names are these**, and they are what you will see in a log,
a trace or an IAM policy:

| wire action | what it is | writes to your zone |
|---|---|---|
| `AddOrgPlatformDomain` | lane 1 registration | no |
| `AddOrgAppDomain` | lane 2 registration | no |
| `AddAppDomain` | lane 3 registration | no |
| `BindAppToOrgAppDomain` | the deploy-time intent, below | **yes** |
| `Verify` | §4 | no |
| `IntentAuthorize` | `authorize`, §4 | no |
| `Complete` | §4 | **yes** |
| `Advance` | §4 | **yes** |
| `Describe` | §4 | no |
| `Orphans` | §4 | no — it is a report |
| `Release` | §4 | no — it revokes at the provider |
| `IntentCapabilities` | `capabilities`, §4 | no |
| `Health` | `health`, §4 | no |

So **three actions can change your zone**: `Complete`, `Advance` and
`BindAppToOrgAppDomain`. Everything else derives, reads, seals or revokes. This
table is the whole of it — the four record-list actions that used to sit beside
these are deleted, and sending one gets `unknown_action`.

🔴 **`IntentAuthorize` and `IntentCapabilities` keep their prefixes.** They are
the names on the wire, so respelling either to the shorter form the record-list
surface used is a version skew, and it presents as `unknown_action` on every
connect rather than as a failed build.

### `AddOrgPlatformDomain(orgId, domain)`

Registers the org's console domain. Derives the four sibling hostnames from a
fixed label table — `account` `api` `apps` `cdn` — so the caller cannot add a
fifth or rename one.

Returns the anchor, the derived hostnames, the ownership proof to publish, the
full record list, and the plan digest. **Touches no credential and writes
nothing.**

### `AddOrgAppDomain(orgId, domain)`

Registers the parent under which the org's apps are auto-routed. Derives exactly
one routing record, the wildcard, plus the ownership proof.

Individual apps are not named here and never need to be: the slug decides the
hostname and the wildcard routes it. What each app still owes is its own
certificate records, and those are minted per app by
`BindAppToOrgAppDomain` below, at deploy time.

### `AddAppDomain(appId, hostname)`

Registers one arbitrary domain against one app. **Takes an app, not an org** —
the owner may be a person, and this lane has to work with no organization
anywhere in the request.

The anchor is the hostname itself, so this is the tightest of the three: nothing
under it is derived, and nothing beside it is reachable.

**This lane is a migration, not a new feature** — see the migration note above.
This intent is what brings it onto the same footing as the other two: the same
provider grant, the same proof at the anchor, the same refusals.

### `BindAppToOrgAppDomain(registration, slug)`

The one intent that runs at **deploy time** rather than at registration.

An org registered `example.net` once with `AddOrgAppDomain`. Every app
it deploys is then routed at `<slug>.example.net` — but the wildcard covers only
routing, and each app still owes the certificate records the wildcard cannot
match. This is the call that mints them.

`registration` is the sealed registration from the org lane; `slug` is the
app's, and
it is **the one caller-chosen string anywhere in this design**. It selects
*which* name under a parent already proven, never *what* is written there — and
it is validated as a single LDH label, so it cannot spell `_acme-challenge`,
`_dmarc`, a leading underscore, a dot, or `*`.

**It has two outcomes, and the second is not a failure:**

| the parent's grant | what happens | what comes back |
|---|---|---|
| live | the records are published for you | `published`, and the app is serving once the edge validates |
| absent, expired or revoked | **nothing is written** | `manual`, with the exact records to add yourself |

That second row is the whole reason this is one call rather than two. A customer
who never authorized — or who revoked, which they are entitled to do at any
moment — gets a working answer instead of an error: here are the records, add
them, and the app comes up. (That list is both the records
[`RECORDS.md`](RECORDS.md) shows for this lane wherever the edge relay is
configured for it, and only the first where it is not — §6.) The private half
does not decide which path is taken and cannot ask for the first one; whether a
usable credential exists is a fact this service establishes by opening the sealed
grant and refreshing it.

The same rule holds everywhere else in this document. `advance` on any lane
degrades the same way, so losing a credential never becomes a stuck domain — it
becomes a list of records and an instruction.

---

## 4 · What happens after you authorize

The same seven for all three lanes, which is the point: one implementation, one
set of refusals, no lane with a weaker path.

### `verify(registration)`

Resolves the ownership proof in **public DNS** and reports whether it is present.

The caller cannot say what to look for and cannot supply a value that makes it
pass — the expected value is recomputed here from the sealed registration. This
is the function that makes "proven" mean something.

### `authorize(registration, codeChallenge)`

Returns the provider's consent URL, and mints the OAuth `state` itself as a
short-lived sealed envelope carrying the lane, the identity, the anchor and a
nonce.

**Refuses unless `verify` passes right now.** The caller echoes the state back
and cannot author one.

On the `org_app_domain` lane it additionally refuses unless this service's own
consent page was served and acknowledged. A wildcard is the one grant whose
scope you cannot enumerate for yourself, so the description you act on comes
from here rather than from a console this repository cannot vouch for. The other
two lanes keep the console's screen: their record sets are closed and listed in
full below.

#### How the acknowledgement is obtained

`GET /consent?registration=…` renders the disclosure and, beneath it, one form
carrying a **challenge**: a MAC over the reference sealed into the registration,
the anchor, and the SHA-256 of the disclosure that was rendered. `POST` the
challenge back to the same URL and this service mints the acknowledgement
`authorize` requires.

**That route is served without the internal secret, and it is the only one that
is.** A page only MirrorStack can read is not a disclosure — no customer's
browser sends `X-MS-Internal-Secret`, so the gate guaranteed the one party who
has to read the page never could. What the page discloses is the derived plan for
one registration, and the only way to name that registration is **the envelope
this service sealed** — ciphertext under its own keyset, carrying a 128-bit
reference — which can be neither guessed nor forged. Holding it already means
having been handed it by the flow, so the secret protected nothing it does not.
Every other route on the transport keeps the gate.

That envelope is therefore the whole gate, and the route is shaped for that: an
absent, malformed, unknown, wrong-lane or unreferenced registration all get one
identical `404` so the page cannot be used to probe what MirrorStack has been
asked to connect (the cause goes to the log); a refused redemption mints the
acknowledgement before it acts on the comparison, so it costs what an accepted
one costs; the answers carry `no-store`, `no-referrer`, and a policy that lets
the page load nothing, post only to itself and be framed by nobody. There is no
request-rate limit and cannot be one — this service owns no database (§7) — only
the two size bounds, 4096 bytes of envelope and 8 KB of form.

**Neither half is an RPC action, and neither may become one.** This Lambda is
IAM-gated, so its only callers are MirrorStack's own services; "serve the page"
and "acknowledge it" as two actions would let the private half call both, and the
control would evaporate into a flag it sets for itself. Both live on the page's
own HTTP route instead, which a deployment reaches through API Gateway.

🔴 **Removing that gate did not make this control stronger.** It is the same
control, finally reachable by the person it exists for. Presence was never proven
and still is not; the private half proxying the page was never excluded and still
is not. What changed is that you can now fetch the disclosure from the service
that will do the writing, rather than reading a console's account of it.

🔴 **What this proves, and what it does not.** An acknowledgement exists only
because this deployment served *this* registration's page showing *these exact
bytes*, and the challenge printed on it came back — so it cannot be minted for a
page that was never rendered, and it stops verifying the moment the disclosure
changes.

It does **not** prove a human read the page. Everything a redemption needs is
printed on the page, so anything that can fetch the page can acknowledge it — and
in production the private half is what proxies the page to you. Nothing this
service can build closes that: a Lambda gated by IAM cannot authenticate a
browser its own caller is standing in front of, and any secret we could put on
the page travels through that same caller. **The control is over sequence and
content, not over presence.** Read it as: *the words you were shown are the words
this code will act on, and they were served by the code that will do the writing*
— not as *a person definitely read them*.

The remaining deployment step is infrastructure, not code: a route to this
function's `/consent` path. Until one exists, the page is served in local
development only and `IntentAuthorize` answers `consent_required` for
`org_app_domain`.

### `complete(state, code, codeVerifier, expectDigest)`

Exchanges the authorization code, seals the resulting credential, and publishes
the records that are knowable at this moment.

**Takes no identity, no lane and no domain** — all three come from the sealed
`state`. That is what makes `authorize` and `complete` cryptographically the same
act, rather than two requests whose fields are checked against each other.

It also **re-resolves the ownership proof itself**, after the digest and before
the code is exchanged. The sealed state is a ten-minute receipt of the check
`authorize` made; without this second look there would be a ten-minute window in
which the proof is already gone and this service still writes.
What a caller compares a customer's reviewed list against is `reviewable` — the
identities `digest` is computed over, returned by the registration intents and by
`describe`. It is deliberately smaller than `records`: that list also carries the
ownership proof, which is the customer's to publish, and on `describe` the
relayed rows too, which arrive *during* the consent window. Binding to `records`
would manufacture a plan-changed refusal out of an upstream answering.

`expectDigest` is **required**; an empty value is refused, because an
integrity check a caller can switch off by omitting a field is a claim rather
than a control. Three things it is *not*, and they matter more than the
requirement does:

- **It defends against a bug in the private half, not against the private
  half.** The value the caller sends is one this service handed it, and this
  service re-derives the plan from the sealed registration and compares. That is
  `derive(reg)` against `derive(reg)`. It catches a plan that moved between the
  screen and the write, and a caller that mangled one in between. It cannot
  catch a caller that faithfully echoes what it was given, because echoing is
  the correct behaviour — so this is not a cross-boundary integrity control, and
  a claim that it is one would be the strongest false claim in this document.
- **It covers the DERIVED records only.** Records 5 and 7 are relayed and their
  bytes do not exist when you review the plan, so they are merged in afterwards
  and checked with a *superset* test — the write set may have grown, never
  shrunk or mutated. They are therefore written with no digest coverage at all.
  What bounds them instead is anchor containment and `internal/relay`'s
  value check, which is the thing to read if that is the part you care about.
- **`advance` takes no digest**, for the same reason: a later pass publishes
  records nobody could have approved, because they did not exist to approve.

Each of those is defensible on its own. The sentence built on top of them —
"the customer's digest is what stops a hostile private half" — is not, which is
why it is not made here.

### `advance(registration, grant)`

One pass of the loop, and the only function *here* that writes after the first
publish — `BindAppToOrgAppDomain` in §3 is the other writer, and it runs this
same code path so that "a later pass degrades the same way on every lane" is
true by construction rather than by intent.

Re-derives the record set, re-checks the ownership proof still resolves, asks AWS
and Cloudflare whether the records they owe have appeared, and publishes whatever
is missing. Returns the rotated credential **even when it fails**, because the
provider rotates on use and a failure that loses the new one strands the grant.

### `describe(registration)`

Read-only. Every record, its purpose, and whether it is present, absent,
conflicting, or the wrong type. Writes nothing, and is the single source for what
a console shows you — so the screen and the writer cannot drift apart.

### `orphans(registration, grant)`

Reports what we left behind when a domain is removed. **A report, never a
mutation.** There is still no delete anywhere in this service, and adding one is
still a design change rather than a refactor: no provider in scope offers a
conditional mutation, so a compensating delete cannot prove it is undoing *our*
write rather than clobbering an edit you made a second ago.

### `release(registration, grant, reason)`

Revokes the refresh token at the provider — that is the one that kills the whole
grant, so there is no second call to make. An envelope that cannot be opened is
reported as such and never guessed at, because a grant we cannot name is one a
human has to end by hand and saying so is the only useful answer.

Two more exist and write nothing: `capabilities()` (`IntentCapabilities`),
which publishes the routing targets, the DCV delegation identifier in force on
each lane and whether it was read from Cloudflare or hand-set, the declared
cadence, the per-lane grant lifetimes and whether a lane needs a consent page —
none of them secret, every one of them a value that ends up in your own zone or
on your own clock — and `health()` (`Health`), which publishes the git SHA this
binary was built from. The publish workflow stamps it at the one build that
produces a deployed artifact; any other build reports `unknown`, so a missing
stamp is visible rather than silent.

Both also carry `resolution`: how many independent vantage points read your
ownership proof, how many must agree, and whether this deployment can actually
reach them. A deployment that cannot meet its own threshold fails `health()`
rather than lowering it — see
[`docs/THREAT-MODEL.md`](THREAT-MODEL.md#we-assume-public-dns-tells-us-the-truth).

The commit is what turns "I read this repository" into "this is the revision
holding my credential", and that step is worth one honest caveat: `Health` sits
behind the same IAM-gated transport as everything else, so today it is auditable
**on request** rather than by your developers unaided.

---

## 5 · What the caller can send, in full

Across every function above, the private half supplies these and nothing else.

| field | where | validation |
|---|---|---|
| `orgId` / `appId` | the three registrations | canonical 36-character hyphenated UUID, strict |
| `domain` | lanes 1 and 2 | one DNS name, ≤253, LDH labels, refused if under a MirrorStack suffix |
| `hostname` | lane 3 — the field is **not** called `domain` | as `domain` above |
| `slug` | `BindAppToOrgAppDomain` | one LDH label. No dot, no leading underscore, no `*` — so it cannot spell `_acme-challenge`, `_dmarc` or a name of its own |
| `code` / `codeVerifier` / `codeChallenge` | `authorize`, `complete` | provider and PKCE; reach no record |
| `expectDigest` | `complete` | required, non-empty, hex. Compared against a plan re-derived here — see §4 for what that does and does not prove |
| `consentToken` | `authorize`, lane 2 only | a MAC under this deployment's key. **Not "ciphertext this service issued"** — it is a signature, over a reference sealed into the registration when the domain was registered. The caller can echo one and can mint none, and there is deliberately no `consentNonce` field beside it: supplying both halves is supplying a statement and your own signature over it |
| `reason` | `release` | **free text, unvalidated.** It is written to this deployment's log and reaches no provider call and no record. It exists so an operator holding a support ticket can tell a domain that was deleted from one whose window simply closed |
| sealed envelopes | everywhere | ciphertext this service issued, opened under associated data naming the lane, the identity and the anchor |

There is no `lane` field, though the lane is inside every envelope: each intent
is its own function, so the lane is a constant at the call site and a caller
cannot get it wrong.

There is **no records field, no value, no target, no proxy flag, no certificate
id, no hostname id, no ownership token, no expiry, no stage.**

A reflection test walks every request struct and **fails on any type it does not
recognise**, so a map or a raw JSON field is rejected by default rather than by
having been thought of.

---

## 6 · What lands in your zone

🔴 **Record 1 changed hands twice, and it is ours again.** The record-list
surface wrote it itself, which is the second defect in §1; the intent surface
made it the customer's and gated every write on it; and it is now published by
this service and gates nothing, because authorize goes straight to the provider.

The name still says `challenge`. It is a marker: it identifies the domain as
registered here, and deleting it stops nothing — see [`RECORDS.md`](RECORDS.md),
which gives every row per lane, and note that revocation at the provider is now
the only control.

| # | name | type | value | lane | written by |
|---|---|---|---|---|---|
| 1 | `_mirrorstack-challenge.<anchor>` | TXT | `HMAC(K, lane‖id‖anchor)` | all three | this service — a marker, not a proof |
| 2 | `account api apps cdn .<anchor>` | CNAME | the org routing target | 1 | this service |
| 3 | `*.<anchor>` | CNAME | the app routing target | 2 | this service |
| 4 | `<hostname>` | CNAME | the app routing target | 3 | this service |
| 5 | `_<token>.<host>` | CNAME | `….acm-validations.aws` | 1 only | relayed from AWS |
| 6 | `_acme-challenge.<host>` | CNAME | `<host>.<uuid>.dcv.cloudflare.com` | all three | this service — **derived** |
| 7 | `_cf-custom-hostname.<host>` | TXT | the serving proof | all three | relayed from Cloudflare |

**Records 5 and 7 are relayed, not derived.** This service derives *that* a proof
must exist and *why*; their bytes come from AWS and Cloudflare. "The engine
derives the record set" is true of which proofs exist and false of every byte,
and both halves of that belong in public.

🔴 **Record 7 is read with MirrorStack's own Cloudflare token, in MirrorStack's
own zone, and the zone is chosen by the LANE.** The org zone and the app/SaaS
zone are separate zones — lane 1's hostnames are CNAMEd into the first and lanes
2 and 3 into the second, which is rows 2 through 4 above seen from the other end
— so one zone id cannot serve three lanes. `CF_SAAS_ORG_ZONE_ID` and
`CF_SAAS_APP_ZONE_ID` name them, the lane selects between them
(`relay.EdgeZones`), and **a hostname never does**: inferring a zone from a
customer's name would let the customer pick which of our zones we authenticate
against.

Both ids come back in `capabilities`, per lane, so a deployment reading lane 1
out of the app zone is visible from outside it. That matters because the
misconfiguration has no other symptom: the wrong zone holds no custom hostname
for the host asked about, which is spelled exactly like a proof Cloudflare has
not minted yet, and the host answers **526 while its certificate reads active**.

The credential is MirrorStack's, not the customer's, and that is a compiler rule
rather than a comment: `internal/shared/cfedge` gives it a defined type the
customer's plain-string grant cannot be assigned to, and `internal/relay` imports
neither the write interface nor any provider adapter. A deployment naming no
zone or no token wires the reader as `nil`, and record 7 is then reported as not
yet available rather than as an error — everything derivable is still published.

**Record 6 is the exception, and it is the most consequential choice here.** It
carries no token — it is a *pointer* at Cloudflare's delegated DCV location, and
both halves of it (the hostname you connected, a per-zone uuid) are known before
anything is asked of anyone. So it is publishable in the first pass, and it never
changes again: Cloudflare mints and rotates the real tokens behind it, in its own
zone, for every future renewal.

🔴 **The uuid is read from Cloudflare rather than configured.** It belongs to a
zone — `GET /zones/{zone_id}/dcv_delegation/uuid`, under the same MirrorStack
token record 7 is read with — so a deployment holding that credential takes it
per lane, and `CF_ORG_DCV_DELEGATION_UUID` is the fallback for one that cannot
ask. **When the two disagree the configured value loses and the disagreement is
logged at ERROR**; `capabilities` reports, per lane, which source won. A hand-set
label silently overriding the provider is how this record came to point at a name
nobody had ever verified.

What that read does *not* settle is the form around the uuid: the endpoint
returns an identifier and no target, so whether the value carries the `<host>.`
prefix is exactly as open as it was, and `derive.DCVTarget` says so.

That single choice removes a whole stage from the flow, and it is what
lets a closed lane hold a credential for 24 hours rather than forever. Cloudflare's
DCV tokens live 7 days on Let's Encrypt and 14 on Google Trust Services; a form
that put the token in the customer's zone would need republishing on that clock,
indefinitely, by a grant we deliberately do not keep.

**The proof value differs per lane**, because the lane is inside the HMAC. A
console proof does not authorize an app-domain wildcard, and neither authorizes a
domain on a single app. Each is a deliberate, separate act.

**No A, AAAA, MX, NS or CAA, ever.** CNAME and TXT only.

---

## 7 · Where your credential lives

**This service still owns no database.** Not by sealing the lifecycle, but by
deleting it: the certificate id, the custom-hostname id and the published-record
cursor are removed from the model and re-read from AWS, from Cloudflare and from
your own zone on every pass.

What stays sealed is a credential and a clock, both monotone-safe under replay —
rolling one back grants no authority it did not already carry. The private half
stores the envelopes and hands them back; it cannot author, edit or reorder one.

The honest limit: a sealed envelope can be **withheld**. The private half can
always decline to advance a domain. What it cannot do is advance one further than
you proved.

---

## 8 · What you can stop, and what you cannot

🔴 **One control, and it is yours alone.** There were two. Deleting the
ownership record is no longer one of them.

**Deleting the ownership marker stops nothing.** It was the second control, and
the reasoning was sound while the record was yours to publish and every write was
gated on it. Neither is true now: this service publishes that record, republishes
it if it goes, and `Authorize`, `Complete` and `Advance` all run whether or not it
resolves. `checkProof` still reads it and still reports what it saw — the reading
travels in the response as a warning — but nothing acts on it.

That is a real reduction, and naming it is the point of this section: a control
that no longer works is worse than one that never existed, because you would plan
around it.

**Revoke at your provider.** Works whether or not we cooperate, takes effect
immediately, and returns you to the manual path above rather than breaking the
domain. Deploys keep working; they just hand you records to add instead of
adding them.

Everything else in this document is a bound we enforce on ourselves and you can
read — with the one exception this file admits rather than omits: the rate floor,
which is declared here and enforced nowhere. These two controls are different in
kind: they are bounds *you* enforce on *us*, and we cannot read them.

### What runs, and when, is declared here — and enforced nowhere

It is not enough for this repository to own every *decision* about your zone if
the schedule that fires them lives somewhere you cannot see. So the clock is
declared here, in `internal/schedule`: the interval, the jitter, the floor and
the backoff, as executable constants, and published again as fields on the
`capabilities()` answer so the two can be compared without cloning anything.

🔴 **The declaration is not a control.** This service holds neither the list of
registrations nor a clock to walk it with. MirrorStack's private half decides
when to call, and `advance` publishes as fast as it is invoked — nothing here
slows a caller that loops.

That cannot be fixed from inside this repository without giving up something
worth more. Enforcing a floor means remembering when a registration was last
touched. That is either a database — the one thing this service does not have,
and the property that lets you read it end to end in an afternoon — or a
timestamp in a sealed envelope the caller stores and hands back. The second is
worse than nothing: an envelope the caller keeps can be replayed from an older
copy, and rolling back a "last touched" grants *more* frequency, not less. It is
the same rollback argument the unsolved problem below turns on, pointed the same
way.

What the declaration does buy is falsifiability. The numbers are published, so a
repair that runs more often than they say is a breach of something written down
rather than an argument about what is reasonable — and where your provider logs
API *access* and not only changes, you can check the rate against your own logs
instead of against our word. Where it logs changes only, the part you cannot
check is the quiet pass: one that finds everything correct writes nothing and
leaves no trace in your zone at all.

### The one we have not solved

**We re-create a record you delete.**

A service with no state cannot count deletions, and a counter in a sealed
envelope is rollback-able in exactly the direction that grants more authority —
so it cannot go there. The honest description of what you are agreeing to is
therefore not "we write once when you authorize", it is:

> we hold write access to names under your anchor, and we continuously enforce a
> desired state there until you stop us.

The two controls above are the stopping. What is missing is anything narrower
than them: there is no way today to say *leave this one name alone* without
revoking the whole grant. If that matters to you, the manual path is the answer,
and it is a supported one rather than a fallback.
