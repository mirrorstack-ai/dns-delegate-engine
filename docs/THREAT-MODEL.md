# Who this service defends you against

Every claim in this repository is a claim against a particular adversary. Stating
which one is what turns "we are careful" into something you can check — and it is
also what tells you which of your own worries this code does *not* answer.

---

## The adversary is MirrorStack

Not an intruder on the internet. **Us.**

The service is invoked by IAM-gated `lambda.Invoke` from MirrorStack's private
half. It sits behind no API Gateway and answers no public route, so an outside
attacker has no way to reach it that does not first involve compromising our AWS
account — at which point this service is not your problem's centre of gravity.

The threat that motivates a public repository is the other one:

> You are about to grant MirrorStack a `dns.write` credential on the zone your
> company's website lives in. What happens if the half of MirrorStack you cannot
> read is wrong, or turns hostile, or is compromised?

So the adversary modelled here is **the caller**: a private half that is buggy,
that has been compromised, or that is deliberately malicious. Everything in this
repository is built to be a bound *we* cannot exceed, and that you can verify
without our cooperation.

That framing has a consequence worth stating plainly: **a check that the private
half can switch off is not a control.** It is a claim. Several things in this
codebase are labelled as such for exactly this reason.

---

## What each party can do

| | you | MirrorStack's private half | this service |
|---|---|---|---|
| choose the domain | ✅ | ✅ | — |
| prove the domain | ✅ **only you** | — | — |
| choose which records exist | — | — | ✅ derived here |
| choose a record's **value** | — | 🔴 **on the legacy surface, yes** | ✅ on the intent surface |
| hold the provider credential | — | as ciphertext it has no key for | ✅ |
| delete a record | ✅ | — | ❌ **no delete exists** |
| stop everything | ✅ **two ways** | — | — |

The two rows in bold are the whole design. The proof is yours, and the stopping
is yours.

---

## Where authorization lives, and why not here

The first thing most readers look for in this repository is a permission check,
and there is not one. That is deliberate, and the reasoning is the same reasoning
as everything above.

**Who inside your organization may connect a domain is decided in MirrorStack's
private half** — an RBAC permission (`domains.write`), a membership probe, and a
role check, all of which this repository cannot see. **This service has no role,
permission or actor concept at all.** Grep for one; there is nothing to find.

It could not have one honestly. This service owns no database, so it cannot read
who is a member of what. The only way it could perform an authorization check is
to accept a claim *from its caller* about that caller's own rights — and the
caller is precisely the party this document says you should not have to trust. A
check evaluated on the attacker's assertion about itself is not a control.

It would also be worse than nothing. A reader seeing an authorization check in a
public repository would reasonably conclude authorization is bounded here, and
they would be wrong. A guard that reads like protection and enforces none is a
recurring failure this codebase refuses in several other places by name; adding
one at the front door would be the largest instance of it.

**So the substitute is different in kind: the bound is not WHO ASKED, it is WHAT
WAS PROVEN.** Anchor containment and the ownership proof bind the outcome no
matter who the caller claims to be. Identity is still bound cryptographically —
the sealed registration and the grant AAD both carry `lane‖identity‖anchor`, so a
grant issued for one organization cannot be replayed onto another's row by a
database write alone — but that is binding, not permission, and the difference is
the point.

### The gap this leaves, stated plainly

This service cannot tell whether its caller is entitled to act for the
organization it names. A compromised private half could register a domain **it
owns** against **your** organization's id, and nothing here would refuse it.

That is a real gap and only the private half's RBAC closes it. Note its
direction, though, because it is not the direction this repository is about: it
is a tenancy problem inside MirrorStack, not a problem in your DNS. Whatever
organization is named, **nothing is written into any zone that somebody did not
prove they control** — and an attacker proving control of their own domain has
gained nothing over yours.

The two layers are not substitutes and neither covers the other's case:

| | protects | against |
|---|---|---|
| RBAC, in the private half | MirrorStack's tenancy model | your own users, and each other's organizations |
| the proof and the anchor, here | **your zone** | **MirrorStack** |

RBAC would not have helped you with the question this repository exists to
answer, because the party it constrains is not the party you are being asked to
trust.

---

## What we assume, and what breaks if the assumption is wrong

An honest threat model is mostly a list of assumptions. These are ours.

### We assume public DNS tells us the truth

`verify()` resolves the ownership proof through whatever resolvers this
deployment was wired with. **Anyone who can lie to all of them can forge a
proof** for a domain they do not own, and unlock a grant.

This is the same problem a certificate authority has, and they answer it three
ways. Two of the three are in this repository now:

- **Multi-perspective validation.** `observe.Quorum` asks N independent
  resolvers and reports a value only when a declared threshold of them serve it.
  One liar out of three produces nothing.
- **Asking the authoritative nameservers directly.** `observe.Authoritative`
  reads the NS records for the zone and queries those servers, which takes the
  recursive cache out of the answer.
- **DNSSEC — not done, and not claimed.** Go's `net.Resolver` does not validate,
  nothing here adds it, and **no signature is checked anywhere in this
  repository**. `capabilities.resolution.dnssec` is a constant `false` so that is
  answerable from the API rather than only from a source file.

🔴 **Read the policy before you authorize, because it is a deployment setting
and not a property of this code.** `IntentCapabilities` returns
`resolution: {vantages, threshold, authoritative, dnssec}`, taken from the
resolver the binary actually wired, and every record in a `verify` or `describe`
answer carries the count its state rests on: `agreement: {asked, agreed,
threshold}`.

**The default is one vantage point — the container's own recursive resolver,
believed on its own**, which is what this service did before the quorum existed.
A quorum is opt-in (`DNS_DELEGATE_RESOLVERS`, `DNS_DELEGATE_AUTHORITATIVE`,
`DNS_DELEGATE_QUORUM`) because a vantage point a deployment cannot reach answers
`unknown`, and `unknown` refuses every authorization.

#### The deployment measures its own egress

Whether a given deployment can reach a nameserver on port 53 is a property of
where it runs, not of this code, so the running service answers it rather than
an operator remembering to. `observe.Probe` resolves a name that must always
resolve at every configured vantage point, on a five-minute TTL, and the result
appears in `IntentCapabilities` and on the health check:

```
resolution.reachability: {reachable, checkedAt, degraded, points: [{vantage, reachable, explain}]}
```

**What you do with it.** If every vantage point you added is `reachable`, this
deployment has the egress the hardening needs — raise `DNS_DELEGATE_QUORUM` and
the customer-visible `threshold` rises with it. If one is not, that vantage point
cannot verify anything, and the fix is the network, not the threshold.

🔴 **`degraded` means broken, not "running with a smaller quorum."** The probe
reports; it never drops an unreachable vantage point so the survivors can meet a
lower bar. Doing that would turn a network fault into a silent reduction of the
threshold a customer read before authorizing — a "2 of 3" verified by one — which
is the exact failure the quorum exists to prevent. So when the reachable set
cannot meet the declared threshold, the published rule stays as it is, every
verification reads `unknown`, and **the health check fails** so the deployment
leaves rotation instead of serving refusals that look like customer mistakes.

What a quorum closes: a single lying recursive resolver, and an off-path cache
poisoner, who has to win the race at every vantage point rather than at one.

What it does not close, at any threshold:

- **An attacker holding your registrar or your authoritative nameservers.**
  Every vantage point then agrees on the same forged answer, and no
  DNS-based validation anywhere survives that.
- **The delegation itself.** `Authoritative` learns *which* servers are
  authoritative through an ordinary resolver, so a forged NS answer redirects
  it. It removes the cache from the proof, not from the delegation.
- **An on-path attacker at our own egress**, who rewrites every vantage point's
  traffic alike.

One direction is deliberately not hardened: agreement that the proof is **gone**
is still absence, and still stops every write. Your stop control must not need a
quorum to work.

There is a second, milder version of the same thing: we see what public DNS
*serves*, which can lag your deletion by the record's TTL. So "deleting the proof
stops every write" is bounded below by a number you chose, not by us.

### We assume your DNS provider enforces the scope it showed you

The grant is scoped by your provider, to one zone. If your provider hands out a
credential broader than its own consent screen described, nothing here would
know. That is a bound we rely on and cannot verify.

Note the asymmetry this creates, because it is the one most people miss:
**your provider's consent screen names a ZONE, and never a subdomain.** Granting
us `dns.write` for `shop.example.com` is, at the provider, a credential over
`example.com` and everything in it. On the intent surface the anchor is what
narrows that back down — which is precisely why the anchor has to be something
you proved rather than something we asserted.

### We assume AWS and Cloudflare return their own records honestly

Two of the seven records are **relayed**, not derived: the ACM validation record
and the Cloudflare serving proof. We derive *that* those proofs must exist and
*why*; their bytes come from the vendor. We bound their shape — the name must sit
beneath a host you connected, the value must name the vendor's own validation
zone, the length and charset are capped — but we cannot verify their content,
because only the vendor knows what the right token is.

### We assume our own keyset stays secret

The ownership proof is an HMAC under a key only this deployment holds. Someone
with that key could compute a proof value — but they would still have to publish
it **in your zone**, which they cannot do. So a leaked keyset does not by itself
let anyone take a domain; it lets them make a proof that only you could satisfy.

---

## What we do NOT defend against, and will not claim to

- **A withheld request.** The private half can always simply decline to advance
  your domain. What it cannot do is advance one further than you proved.
- **Re-creating a record you delete.** A stateless service cannot count
  deletions, and a counter in a sealed envelope is rollback-able in the direction
  that grants more authority. So the honest description of the grant is not "we
  write once" — it is: *we hold write access to names under your anchor, and we
  continuously enforce a desired state there until you stop us.*
- **A narrower stop than "all of it".** There is no way today to say *leave this
  one name alone* without revoking the whole grant. If that matters to you, the
  manual path is the answer, and it is supported rather than a fallback.
- **Us, before you authorize.** If you never grant anything, no credential of
  yours exists anywhere in MirrorStack, and nothing in this repository can touch
  your zone at all.

---

## How the claims are checked

Reading is the point, but reading is not proof. Three things back it up, in
increasing order of how much they would survive a determined sceptic:

1. **Example tests.** ~5,000 lines. They encode the cases we thought of.
2. **Fuzz targets** over the pure rules — containment, validation, derivation,
   envelope opening, observation. They assert that *everything accepted*
   satisfies the invariant, which covers the cases we did not think of. Run
   `go test -fuzz Fuzz<Name> ./internal/<pkg>/` on your own clone.
3. **A mutation pass** ([`MUTATION.md`](MUTATION.md)), which breaks each
   invariant on purpose and records which test noticed. It is the only one of the
   three that can tell you a test is decorative — and it has already caught one
   that was.

None of these needs a network, a database, or a Cloudflare account. That is
deliberate: a safety property you can only check by trusting our staging
environment is a safety property you cannot check.
