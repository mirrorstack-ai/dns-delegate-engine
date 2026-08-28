package consent

import (
	"fmt"
	"html/template"
	"strings"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/derive"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/lane"
)

// Page renders the consent page for a registration: the anchor, the wildcard
// that will be published, that the grant is STANDING rather than 24 hours, what
// it can and cannot reach, and the two controls the customer keeps — delete the
// ownership proof, or revoke at the provider.
//
// 🔴 IT IS A LEGAL-WEIGHT DISCLOSURE, NOT A SCREEN. What comes back is the
// entire text a customer is asked to agree to before a standing credential over
// their zone exists, and the acknowledgement Token mints refers to it. Every
// sentence in it has to be true of the code in this repository, which is the
// reason the page is built here rather than anywhere a product decision could
// reach it. Two consequences worth stating plainly, because they look like
// omissions:
//
//   - It has no call to action, no button and no form. This function renders a
//     description; collecting the agreement belongs to whatever serves the page,
//     and keeping the two apart is what keeps a render from becoming an
//     acknowledgement (see Token).
//   - It fetches nothing. No script, no image, no font, no external stylesheet,
//     no link — the source contains no `src` and no `href` at all, so "this page
//     made no request and reported nothing about you" is checkable by reading it
//     rather than by trusting us. A consent screen that phoned home while asking
//     for consent would be answering the customer's question the wrong way. The
//     one <style> block is inline, and TestPageLoadsNothingAndPostsNowhere is
//     what keeps that the only one.
//
// The nonce is the page's reference: it is printed on the page and it is inside
// the acknowledgement, which is what ties a token to the exact text that was
// shown. Page and Token agree on what a usable (nonce, anchor) pair is because
// Page asks Token's own validator — a page that cannot be acknowledged is not
// worth serving.
//
// 🔴 THE ONLY DEFENCE AGAINST A HOSTILE VALUE HERE IS CONTEXTUAL ESCAPING, AND
// THAT IS DELIBERATE.
//
// Every string this page renders — the anchor, a record's name, a routing
// target, an explanation — goes through html/template, which escapes for the
// context it lands in. What this function does NOT do is re-check that the
// anchor is a syntactically valid DNS name. lane.ValidateDomain does that where
// domains enter the service, and internal/derive runs it before a plan exists;
// repeating it here would be a second copy of a rule to drift, and, worse, it
// would tempt a later reader into believing the escaping is a formality that
// something upstream has already made unnecessary. It has not. The escaping is
// unconditional so that it keeps holding the day the checks upstream are
// reordered, and TestPageEscapesEveryValueItRenders drives a plan through here
// that no validator would ever have passed, precisely to prove the escaping does
// not depend on one.
//
// What it does check is SEMANTIC rather than syntactic: that the plan describes
// the grant this page's sentences are about. See the refusals below.
func Page(p derive.Plan, nonce string) (string, error) {
	// 🔴 THE PAGE'S CENTRAL CLAIM IS A LANE-2 CLAIM. Rendering it for another
	// lane would tell a customer their closed, 24-hour, four-record grant is a
	// standing wildcard — and would mint an acknowledgement saying they had been
	// told so. Note the asymmetry with Required, which fails closed in the other
	// direction: an unrecognised lane is REQUIRED to have a page and CANNOT be
	// given one, so it is blocked rather than described wrongly.
	if p.Lane != lane.OrgAppDomain {
		return "", fmt.Errorf("%w: this page describes the %s grant, not %q",
			ErrConsent, lane.OrgAppDomain, echo(string(p.Lane)))
	}
	// Unreachable today, and retained. The page says, in its own words, that this
	// grant has no expiry; package lane is where that is actually decided. If the
	// lane table ever gives lane 2 a bounded lifetime, this refusal is what
	// forces whoever changed it to come and rewrite the page, instead of leaving
	// a disclosure that is confidently wrong about the one property it exists to
	// disclose.
	if p.Lane.GrantLifetime() != lane.Standing {
		return "", fmt.Errorf("%w: %s no longer holds a standing grant, and this page says it does",
			ErrConsent, lane.OrgAppDomain)
	}

	anchor := dnsplan.NormalizeName(p.Anchor)
	// message is Token's validator, called here for its refusals. It bounds the
	// anchor and the reference and rejects a separator in either, so every page
	// this function returns is one an acknowledgement can be minted for.
	if _, err := message(nonce, anchor); err != nil {
		return "", err
	}
	// dnsplan.MaxRecords is the publish boundary's bound, reused rather than
	// chosen again: the page and the writer disagreeing about how many records a
	// plan may hold would mean a customer consenting to a set that is then
	// refused, or — the direction that matters — a set larger than the one they
	// were shown.
	if len(p.Items) == 0 || len(p.Items) > dnsplan.MaxRecords {
		return "", fmt.Errorf("%w: a plan of %d records describes no grant a customer can agree to",
			ErrConsent, len(p.Items))
	}

	var ownership, routing *derive.Item
	rows := make([]pageRow, 0, len(p.Items))
	for i := range p.Items {
		item := p.Items[i]
		if err := checkItem(anchor, item); err != nil {
			return "", err
		}
		switch item.Purpose {
		case derive.PurposeOwnership:
			if ownership != nil {
				return "", fmt.Errorf("%w: the plan holds two ownership proofs, and only one of them stops us", ErrConsent)
			}
			ownership = &p.Items[i]
		case derive.PurposeRouting:
			if routing != nil {
				return "", fmt.Errorf("%w: the plan holds two routing records, and this lane publishes one", ErrConsent)
			}
			routing = &p.Items[i]
		}
		rows = append(rows, pageRow{
			Name:    item.Record.Name,
			Type:    item.Record.Type,
			Value:   item.Record.Value,
			Writer:  writerWord(item.Source),
			Explain: item.Explain,
		})
	}

	// The ownership row is required because the page's first stop control names
	// it: "delete this record and every write stops". A page that gave that
	// instruction without naming the record would be handing a customer a
	// control they cannot find, and its source must be the customer — a proof we
	// write ourselves proves nothing, and the sentence would be false of a row we
	// publish.
	if ownership == nil {
		return "", fmt.Errorf("%w: the plan carries no ownership proof, so the page cannot name what to delete", ErrConsent)
	}
	if ownership.Source != derive.SourceCustomer {
		return "", fmt.Errorf("%w: the ownership proof is marked %q rather than %q, and a proof we publish is not a stop control",
			ErrConsent, echo(string(ownership.Source)), derive.SourceCustomer)
	}
	// The wildcard is the grant. It has to be present, it has to be ours to
	// write, and it has to be the wildcard AT THIS ANCHOR — the page names it in
	// its heading, so a plan whose routing record is some other name would be
	// consented to under a description of a name it does not contain. A per-app
	// bind plan (derive.BindApp) lands here: it has no routing record at all,
	// which is correct, and it is not a plan anybody authorizes.
	if routing == nil {
		return "", fmt.Errorf("%w: the plan publishes no wildcard, so there is no standing grant to describe", ErrConsent)
	}
	if routing.Source != derive.SourceDerived {
		return "", fmt.Errorf("%w: the wildcard is marked %q rather than %q",
			ErrConsent, echo(string(routing.Source)), derive.SourceDerived)
	}
	if wildcard := "*." + anchor; routing.Record.Name != wildcard {
		return "", fmt.Errorf("%w: the routing record is %q, and this page describes %q",
			ErrConsent, echo(routing.Record.Name), wildcard)
	}

	data := pageData{
		Anchor:        anchor,
		Wildcard:      routing.Record.Name,
		RoutingTarget: routing.Record.Value,
		ProofName:     ownership.Record.Name,
		ProofValue:    ownership.Record.Value,
		// Built from the anchor rather than from a record, because these are the
		// names that do NOT exist yet — the whole reason this page exists. The
		// placeholder is where the app's own slug goes.
		PerAppCert:    dcvPrefix + slugPlaceholder + "." + anchor,
		PerAppServing: servingPrefix + slugPlaceholder + "." + anchor,
		PerAppHost:    slugPlaceholder + "." + anchor,
		Reference:     strings.TrimSpace(nonce),
		Rows:          rows,
	}
	var out strings.Builder
	if err := pageTemplate.Execute(&out, data); err != nil {
		// Retained rather than assumed away. Every field is a string and the
		// template has no function calls, so there is nothing here that fails at
		// runtime today; a half-written page is the one outcome that must never
		// be returned as a page, because a disclosure truncated mid-sentence is
		// a disclosure that omits whichever paragraph came last.
		return "", fmt.Errorf("%w: the consent page did not render: %w", ErrConsent, err)
	}
	return out.String(), nil
}

// checkItem refuses a row this page cannot honestly display.
//
// It is deliberately the same shape as derive.checkItem — and deliberately not
// the same code, because this package must not be the reason a plan is
// considered safe. derive refuses to BUILD these; this refuses to SHOW them, and
// the two agreeing is a property worth having twice: a row that reached here
// unlabelled, proxied, of an unknown type or outside the anchor came from
// somewhere other than derive, and a consent page is the last place to find that
// out quietly.
func checkItem(anchor string, item derive.Item) error {
	record := item.Record
	if record.Type != "CNAME" && record.Type != "TXT" {
		return fmt.Errorf("%w: the plan holds a %q record, and the vocabulary is CNAME and TXT",
			ErrConsent, echo(record.Type))
	}
	if record.Name == "" || record.Value == "" {
		// Empty is the dangerous half-formed case: a blank owner name is a write
		// at the zone apex, and a blank cell in a disclosure is a customer
		// agreeing to something nobody wrote down.
		return fmt.Errorf("%w: the plan holds an incomplete %s record", ErrConsent, record.Type)
	}
	if item.Explain == "" || item.Source == "" || item.Purpose == "" {
		return fmt.Errorf("%w: %q has no explanation to show, and an unexplained row is not consented to",
			ErrConsent, echo(record.Name))
	}
	if record.Proxied {
		// There is no column for this, and adding one would document a capability
		// this service does not have: a customer-zone record is never proxied
		// (see derive.routingItem). Refusing is how the page stays true.
		return fmt.Errorf("%w: %q is marked proxied, and a customer-zone record never is",
			ErrConsent, echo(record.Name))
	}
	if !dnsplan.Contains(anchor, record.Name) {
		// Both sentinels: a caller checking this package keeps one answer, and an
		// operator grepping the service for every containment failure finds this
		// one too. A page listing a record outside the anchor would be asking for
		// consent to a write the publisher would refuse — and the acknowledgement
		// it produced would be evidence of an agreement that never applied.
		return fmt.Errorf("%w: %w: %q is not at or under %q",
			ErrConsent, dnsplan.ErrAnchorEscape, echo(record.Name), echo(anchor))
	}
	return nil
}

const (
	// dcvPrefix and servingPrefix are the owners of records 6 and 7
	// (docs/DESIGN.md §6). They are the same literals as internal/derive's
	// dcvPrefix and internal/relay's ownershipRecordPrefix, which are unexported
	// in packages that have no business exporting them for a renderer's benefit.
	// TestPerAppNamesMatchWhatBindAppDerives pins this copy of the first against
	// a plan derive actually produces; the second has no equivalent, because
	// building one would need a Cloudflare answer, and that is stated here rather
	// than left to be discovered.
	dcvPrefix     = "_acme-challenge."
	servingPrefix = "_cf-custom-hostname."

	// slugPlaceholder stands where an app's own slug goes in a name that does
	// not exist yet. The angle brackets are what a developer expects in a
	// placeholder, and they are also HTML metacharacters — they reach the page
	// as data and are escaped like every other value, which is the behaviour
	// under test rather than an exception to it.
	slugPlaceholder = "<your-app>"
)

// pageData is everything the template renders. Strings only, and no method on
// it: a template that can call code can call code that fails halfway through a
// disclosure.
type pageData struct {
	Anchor        string
	Wildcard      string
	RoutingTarget string
	ProofName     string
	ProofValue    string
	PerAppHost    string
	PerAppCert    string
	PerAppServing string
	Reference     string
	Rows          []pageRow
}

// pageRow is one record as the page displays it. Purpose is not a column: the
// Explain sentence says what the row is for in words a person can act on, and a
// one-word category beside it would be the part a reader skims to instead.
type pageRow struct {
	Name    string
	Type    string
	Value   string
	Writer  string
	Explain string
}

// writerWord is the answer to the only question anybody asks about an
// unfamiliar row in their own zone: who put it there.
//
// An unrecognised source renders as itself rather than as a blank or a guess. A
// blank cell in this column would read as "nobody", which is the one answer that
// is never true, and it is exactly what a derive.Source constant added later
// would produce if this map fell back to the empty string.
func writerWord(source derive.Source) string {
	switch source {
	case derive.SourceCustomer:
		return "you, by hand"
	case derive.SourceDerived:
		return "MirrorStack"
	case derive.SourceRelayed:
		return "MirrorStack, relayed from AWS or Cloudflare"
	}
	return string(source)
}

// echo bounds what a refusal quotes back, for the reason lane.echo gives: an
// error string is somewhere a value gets copied, logged, and copied again.
func echo(s string) string {
	const max = 64
	if len(s) > max {
		return s[:max] + "…(truncated)"
	}
	return s
}

// pageTemplate is parsed once, at init, with Must.
//
// A parse failure is a defect in the constant below rather than a condition any
// request can produce, so it belongs at process start where CI and a deploy both
// see it — not as an error returned to the one customer unlucky enough to be
// mid-consent when it ships.
//
// 🔴 EVERY ACTION IN IT IS A PLAIN {{.Field}} ON A STRING. html/template escapes
// for the context each one lands in, and that guarantee is only worth having
// while nothing here is a template.HTML, a template.JS or a template.URL. There
// are none, there is no <script>, and there is no attribute whose value comes
// from data — so no value on this page is ever one escaping decision away from
// being executable.
var pageTemplate = template.Must(template.New("consent").Parse(pageMarkup))

const pageMarkup = `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Authorize MirrorStack for {{.Anchor}}</title>
<style>
:root { color-scheme: light dark; }
body { margin: 0; padding: 2.5rem 1.25rem 4rem;
  font: 16px/1.65 system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: #1a1a1a; background: #ffffff; }
main { max-width: 45rem; margin: 0 auto; }
h1 { font-size: 1.55rem; line-height: 1.25; margin: 0 0 .75rem; }
h2 { font-size: 1.05rem; margin: 2.5rem 0 .75rem; padding-top: 1.25rem; border-top: 1px solid #d9d9d9; }
p, li { margin: .75rem 0; }
ul { padding-left: 1.15rem; }
.lede { font-size: 1.05rem; color: #333333; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .9em; word-break: break-all; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { text-align: left; vertical-align: top; padding: .5rem .6rem;
  border-bottom: 1px solid #e4e4e4; font-size: .92rem; }
th { font-weight: 600; background: #f6f6f6; white-space: nowrap; }
td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .85rem; word-break: break-all; }
tr.why td { border-bottom: 2px solid #d9d9d9; color: #444444; font-size: .88rem; padding-top: 0; }
.note { border-left: 3px solid #b00020; padding: .15rem 0 .15rem 1rem; margin: 1.5rem 0; }
.note p:first-child { margin-top: 0; }
.note p:last-child { margin-bottom: 0; }
.ref { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #d9d9d9;
  color: #555555; font-size: .85rem; }
@media (prefers-color-scheme: dark) {
  body { background: #101010; color: #e9e9e9; }
  .lede { color: #cfcfcf; }
  h2, .ref { border-color: #333333; }
  th { background: #1b1b1b; }
  th, td { border-color: #2b2b2b; }
  tr.why td { border-bottom-color: #333333; color: #b8b8b8; }
  .note { border-left-color: #ff6b6b; }
  .ref { color: #a2a2a2; }
}
</style>
<main>

<h1>Authorize MirrorStack to publish DNS records under <code>{{.Anchor}}</code></h1>

<p class="lede">One record now — <code>{{.Wildcard}}</code> pointing at
<code>{{.RoutingTarget}}</code> — and, from then on, certificate records for apps
you have not deployed yet, under a grant with <strong>no expiry</strong>.</p>

<p>This page is served by the service that will do the writing, not by the
console that asked for it. It fetches nothing and reports nothing: no script, no
image, no font, no third-party request of any kind — every byte of it is in this
one document, which you can confirm by reading its source.</p>

<h2>Why this screen is not part of the console</h2>

<p>MirrorStack's other two domain types publish a <em>closed</em> set of records.
Connecting a console domain writes under four hostnames named from a fixed table;
connecting a domain to a single app writes at that one hostname and nowhere else.
Both sets can be listed in full before you agree to anything, so a console screen
can show you the whole of it.</p>

<p>A wildcard cannot be listed. <code>{{.Wildcard}}</code> is a standing
permission to write names <em>that do not exist yet</em> — every app your
organization will ever deploy, at hostnames nobody has chosen. You are not
agreeing to a list; you are agreeing to a rule. The only honest place to read a
rule is the code that applies it, which is why this description comes from there
and not from a screen this repository cannot vouch for.</p>

<h2>The grant is standing</h2>

<p><strong>Standing means there is no expiry date.</strong> The credential is
held until you end it. MirrorStack's other two domain types hold a credential for
24 hours, because the records they exist to write are known when you authorize
and are finished shortly afterwards. This one is not: the records it exists to
write belong to apps that have not been created, so a window that closed would
mean every future deployment on this domain needing a manual DNS step, forever.</p>

<p>That is the trade, and it is the thing to think hardest about on this page.
It ends when you revoke at your DNS provider, when you delete the ownership proof
named below, or when MirrorStack releases it — which it does when this domain is
removed. What it does not do is end on a clock.</p>

<h2>What the credential can reach</h2>

<div class="note">
<p><strong>The permission your provider issues covers your whole zone.</strong>
There is no narrower one to ask for: no provider this service supports offers a
permission scoped to a <em>name</em> rather than to a zone. So the apex,
<code>www</code>, your mail records and everything else in that zone are inside
what the credential technically permits.</p>
<p>The bound is therefore <em>ours</em>, enforced in code you can read, rather
than your provider's. It is worth knowing which of the two you are relying on.</p>
</div>

<p>What this service will do with it, in full:</p>

<ul>
<li><strong>Only names at or under <code>{{.Anchor}}</code>.</strong> Checked
twice, in two different places: once where the record set is derived, and again
at the boundary that hands records to your provider. A name that fails either
check does not narrow the write — it refuses the whole plan, so a plan cannot be
partly written on the strength of a bound it broke.</li>
<li><strong>Only <code>CNAME</code> and <code>TXT</code> records.</strong> No
<code>A</code>, <code>AAAA</code>, <code>MX</code>, <code>NS</code> or
<code>CAA</code>, ever. Your mail routing and your certificate authority policy
are outside the vocabulary this service has.</li>
<li><strong>Nothing is ever deleted.</strong> There is no delete method anywhere
in this service, on any code path, for any reason. Adding one is a design change
and a broken promise, not a refactor.</li>
<li><strong>A name you are already serving from is not taken.</strong> If a
hostname we want to route already answers with a <code>CNAME</code> that is not
ours, the write is refused, yours is left exactly as it is, and the refusal names
what it found. You delete it yourself and authorize again — the only sequence in
which that change was ever yours to make. The one exception is a record that is
already ours, which is repaired in place. The honest limit: the comparison is
per record type, so an <code>A</code> record where a <code>CNAME</code> is wanted
is left for your provider to reject rather than caught here.</li>
<li><strong>A wildcard answers only what your zone does not.</strong>
<code>{{.Wildcard}}</code> is consulted for a name only when your zone holds no
record of its own for it, so everything you publish today keeps resolving exactly
as it does today, and anything you add later takes precedence over it.</li>
</ul>

<h2>What lands in your zone now</h2>

<div class="scroll">
<table>
<tr><th>Record</th><th>Type</th><th>Value</th><th>Written by</th></tr>
{{range .Rows}}<tr>
<td class="mono">{{.Name}}</td>
<td>{{.Type}}</td>
<td class="mono">{{.Value}}</td>
<td>{{.Writer}}</td>
</tr>
<tr class="why"><td colspan="4">{{.Explain}}</td></tr>
{{end}}</table>
</div>

<h2>And two more records per app, as you deploy</h2>

<p>A wildcard matches exactly one label. <code>{{.Wildcard}}</code> therefore
covers <code>{{.PerAppHost}}</code> and does <em>not</em> cover anything one
label further left — which is where a certificate's validation records live. So
each app you deploy under this domain adds two records of its own:</p>

<div class="scroll">
<table>
<tr><th>Record</th><th>Type</th><th>What it is</th></tr>
<tr>
<td class="mono">{{.PerAppCert}}</td>
<td>CNAME</td>
<td>A pointer to where Cloudflare keeps that app's certificate validation
token — in Cloudflare's own zone, not in yours. It carries no token itself,
and it never changes again: renewals rotate the token behind the pointer.</td>
</tr>
<tr>
<td class="mono">{{.PerAppServing}}</td>
<td>TXT</td>
<td>A separate proof Cloudflare asks for before it will serve that hostname.
Its value is minted by Cloudflare and republished here verbatim.</td>
</tr>
</table>
</div>

<p>These are what the standing credential is for. They cannot be written when you
authorize, because the app they belong to does not exist yet. If the credential
is gone when an app is deployed — revoked, or never granted — nothing is written
and MirrorStack hands you these two records to add yourself instead. The app
still works; you add them by hand.</p>

<h2>What you can stop, and how</h2>

<p><strong>Delete the ownership proof.</strong> This record, in your zone:</p>

<div class="scroll">
<table>
<tr><th>Record</th><th>Type</th><th>Value</th></tr>
<tr><td class="mono">{{.ProofName}}</td><td>TXT</td><td class="mono">{{.ProofValue}}</td></tr>
</table>
</div>

<p>MirrorStack cannot publish that record — a proof we wrote ourselves would
prove nothing — and it is re-checked on every pass. Delete it and every write
from this service stops within one pass. Nothing needs to reach MirrorStack for
that to take effect, and nobody here can undo it.</p>

<p><strong>Revoke at your DNS provider.</strong> This works whether or not
MirrorStack cooperates, takes effect immediately, and does not break your domain:
it returns you to adding records by hand. Deployments keep working — they hand
you a list instead of publishing it.</p>

<h2>What we have not solved</h2>

<div class="note">
<p><strong>We re-create a record you delete.</strong> This service keeps no
database, so it cannot remember that you removed something on purpose; the next
pass finds the record missing and publishes it again. The honest description of
what you are agreeing to is therefore not "MirrorStack writes some records once",
it is: <em>MirrorStack holds write access to names under
<code>{{.Anchor}}</code>, and continuously enforces a desired state there until
you stop it.</em></p>
<p>The two controls above are the stopping, and there is nothing narrower than
them: <strong>there is no way today to say "leave this one name alone" without
revoking the whole grant.</strong> If that matters to you, adding the records by
hand and granting nothing is a supported path rather than a fallback — the list
you would be given is derived by this same code.</p>
</div>

<p class="ref">Reference <code>{{.Reference}}</code> — this page was generated by
MirrorStack's dns-delegate-engine for <code>{{.Anchor}}</code>. Acknowledging it
produces a token bound to that reference and that domain, which authorizes
nothing on its own and expires with this attempt.</p>

</main>
</html>
`
