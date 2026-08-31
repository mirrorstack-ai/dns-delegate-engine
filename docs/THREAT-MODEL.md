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
| choose a record's **value** | — | — | ✅ derived here |
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

🔴 **This section describes a control that no longer exists.** The ownership
record stopped gating publication, and MirrorStack publishes it (see
`docs/RECORDS.md`), so deleting it stops nothing and the readings above are
reported rather than acted on.

The stop control is now revocation at your DNS provider: it takes effect
immediately, needs no quorum, needs no lookup to succeed, and does not depend on
MirrorStack cooperating — which are the properties this section was written to
guarantee. They are stronger there than they ever were here, because they do not
rest on a reading of public DNS at all.

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

## Why we hold access to your whole Cloudflare account

You will notice this on the consent screen, and it is the right thing to notice.

🔴 **Cloudflare's OAuth scopes are permission TYPES, never resources.** `dns.write`
means "DNS writes", not "DNS writes on example.com". There is no zone-scoped
OAuth grant to ask for — only API *tokens* can be restricted to a zone, and
tokens have no consent flow. So the grant you give reaches, in principle, every
zone in the account you authorized. We cannot narrow it by asking differently.

What actually bounds it is four things, and three of them are not our promises:

1. **Cloudflare bounds it to the account you chose.** `FindZone` resolves the
   zone through YOUR token — see `internal/provider/cloudflare`, which walks the
   hostname's parents until an authorized zone answers. A name outside the
   granting account has no authorized zone, so there is nothing to write into.
   That is Cloudflare's enforcement, not ours.

2. **The anchor bounds it to one domain.** Every write is refused unless the name
   is at or under the anchor sealed into the registration — `internal/derive`,
   and again at the publish boundary in `internal/dnsplan`. The seal is under a
   key MirrorStack's private half does not hold, so it cannot author or edit one.

3. **You saw the anchor before you authorized.** The console names the domain and
   lists every record it will write, and the digest of that list is what
   `Complete` refuses to run without. If the domain on that screen was not yours,
   the answer was to cancel.

4. **Nothing is ever deleted.** `internal/reconcile` creates and patches; it has
   no delete path. So the worst outcome of a mistake is extra records you can see
   and remove.

**The residual, stated plainly.** MirrorStack's private half chooses the anchor.
Combined with (1), a bug there could target the wrong zone — but only one of YOUR
zones, inside the account you already authorized, writing records you can see and
delete. It cannot reach another customer, and it cannot reach an account you did
not grant.

That used to be narrower: an ownership proof you published, which this service
could not write, was checked before any authorization was minted. It is gone —
see `RECORDS.md` — and this section is what remains in its place.

**If that is not enough for you, it does not have to be.** Put the delegated
domain in a Cloudflare account of its own: account-wide is then zone-wide, the
consent screen lets you pick which account, and nothing above changes.

## How to check that the code you are reading is the code we run

Everything above is a claim about source you can read. What touches your DNS is a
compiled artifact in a private bucket, so until you can tie the two together, all
of it reduces to trusting us — which is the opposite of why this repository is
public.

Three steps, all on public infrastructure, none of them needing anything from
MirrorStack:

```
# 1. ask the running service which build it is
curl https://account.<your-org-domain>/dns-consent/healthz
    -> {"ok":"true","commit":"<sha>"}

# 2. verify that artifact was built from this repository, at that commit
gh attestation verify <artifact> --repo mirrorstack-ai/dns-delegate-engine

# 3. read that exact commit
git -C dns-delegate-engine show <sha>
```

Step 2 works because `.github/workflows/publish.yml` records a Sigstore-signed
SLSA provenance statement binding each artifact's SHA-256 to this repository,
this commit and that workflow, before the artifact is uploaded.

🔴 **The limit, stated so a reviewer does not have to find it.** This proves the
artifact was built from the source, and that the service reports that commit. It
does NOT prove the Lambda AWS runs is that artifact — the build stamp is
self-reported, and an operator determined to lie could ship a binary that lies.
What it removes is the *unfalsifiable* version of the claim: a lie now requires
deliberately building and deploying a divergent artifact, rather than merely
saying something untrue about code nobody could match to a deployment.

If `commit` reads `unknown`, the binary was not built by the publish workflow and
nothing above applies to it.

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
