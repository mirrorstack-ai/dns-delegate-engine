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

## What we assume, and what breaks if the assumption is wrong

An honest threat model is mostly a list of assumptions. These are ours.

### We assume public DNS tells us the truth

`verify()` resolves the ownership proof through a recursive resolver. **Anyone
who can lie to that resolver can forge a proof** for a domain they do not own,
and unlock a grant.

This is the same problem a certificate authority has, and they answer it with
multi-perspective validation, DNSSEC checking, and querying authoritative
nameservers directly. **We do none of that yet.** It is the largest unclosed
assumption in this repository and it is tracked in
[`SECURITY.md`](../SECURITY.md).

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
