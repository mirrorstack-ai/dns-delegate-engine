package dnsplan_test

import (
	"errors"
	"fmt"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
)

// The ids and tokens below are the shapes real values take, with the values
// themselves replaced. A target id is a canonical UUID because the digest binds
// the plan to one row; an ownership token and a certificate token are opaque
// strings neither side chooses.
const (
	exampleTargetID  = "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607"
	exampleOwnership = "ms-verify-7f3a9c21e4b8d05f6a1c3e7b9d2f4a68"
)

// A MirrorStack console connected at your own hostname.
//
// This is the WHOLE plan for one connected hostname: the shared proof at the
// name you own, the record that routes traffic, and the two records a
// certificate authority reads. A console connect covers up to four sibling
// hostnames (account, api, apps and cdn under the domain you registered) and
// each one contributes the same shape — one routing record and its own
// certificate records. The proof at the anchor is shared, and there is only ever
// one of it.
//
// Read the `routing` line first. It is the only record here a browser ever
// follows, and therefore the only one whose removal takes a hostname down.
func ExampleSnapshot_Explain_platformDomain() {
	plan, err := dnsplan.NewSnapshot(dnsplan.KindPlatform, exampleTargetID, "example.com", []dnsplan.Record{
		{Type: "TXT", Name: "_mirrorstack-challenge.example.com", Value: exampleOwnership},
		{Type: "CNAME", Name: "account.example.com", Value: "connect.mirrorstack.ai"},
		{Type: "CNAME", Name: "_9f8c7b6a5e4d3c2b1a0f.account.example.com", Value: "_1a2b3c4d5e6f7890abcd.acm-validations.aws"},
		{Type: "TXT", Name: "_acme-challenge.account.example.com", Value: "e3b0c44298fc1c149afbf4c8996fb924"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("anchor:", plan.Anchor)
	for _, line := range plan.Explain() {
		fmt.Println(line)
	}
	// Output:
	// anchor: example.com
	// ownership   TXT   _mirrorstack-challenge.example.com           ms-verify-7f3a9c21e4b8d05f6a1c3e7b9d2f4a68   DNS-only
	// routing     CNAME account.example.com                          connect.mirrorstack.ai                       DNS-only
	// certificate CNAME _9f8c7b6a5e4d3c2b1a0f.account.example.com    _1a2b3c4d5e6f7890abcd.acm-validations.aws    DNS-only
	// certificate TXT   _acme-challenge.account.example.com          e3b0c44298fc1c149afbf4c8996fb924             DNS-only
}

// An app domain, where every app you deploy gets a hostname under one parent.
//
// One wildcard is all the ROUTING a customer ever publishes here — but it is not
// all the DNS. `*.example.app` matches exactly one label, so it covers
// `blog.example.app` and never `_acme-challenge.blog.example.app`. Each app
// therefore still owes one certificate record of its own, published when that
// app is created. That is the reason this grant is standing rather than
// 24 hours: the records it exists to write are for apps that do not exist yet.
func ExampleSnapshot_Explain_appDomain() {
	plan, err := dnsplan.NewSnapshot(dnsplan.KindApp, exampleTargetID, "example.app", []dnsplan.Record{
		{Type: "CNAME", Name: "*.example.app", Value: "connect.mirrorstack.app"},
		{Type: "TXT", Name: "_mirrorstack-challenge.example.app", Value: exampleOwnership},
		{Type: "TXT", Name: "_acme-challenge.blog.example.app", Value: "5d41402abc4b2a76b9719d911017c592"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("anchor:", plan.Anchor)
	for _, line := range plan.Explain() {
		fmt.Println(line)
	}
	// Output:
	// anchor: example.app
	// routing     CNAME *.example.app                                connect.mirrorstack.app                      DNS-only
	// ownership   TXT   _mirrorstack-challenge.example.app           ms-verify-7f3a9c21e4b8d05f6a1c3e7b9d2f4a68   DNS-only
	// certificate TXT   _acme-challenge.blog.example.app             5d41402abc4b2a76b9719d911017c592             DNS-only
}

// Connecting a subdomain cannot reach the rest of your zone.
//
// The anchor is the exact name you proved you own. If you connect
// `shop.example.com`, then `example.com`, `www.example.com` and your mail
// records are all OUTSIDE it, and a plan naming any of them is refused whole —
// before a credential is touched, so nothing partial is written.
func ExampleNewSnapshot_refusesAnythingOutsideTheAnchor() {
	for _, name := range []string{
		"shop.example.com",     // the anchor itself
		"www.shop.example.com", // under the anchor
		"www.example.com",      // a sibling — NOT under it
		"example.com",          // the parent — NOT under it
		"shop.example.com.evil.test",
	} {
		_, err := dnsplan.NewSnapshot(dnsplan.KindPlatform, exampleTargetID, "shop.example.com",
			[]dnsplan.Record{{Type: "CNAME", Name: name, Value: "connect.mirrorstack.ai"}})
		switch {
		case errors.Is(err, dnsplan.ErrAnchorEscape):
			fmt.Printf("refused  %s\n", name)
		case err != nil:
			fmt.Printf("refused  %s (%v)\n", name, err)
		default:
			fmt.Printf("allowed  %s\n", name)
		}
	}
	// Output:
	// allowed  shop.example.com
	// allowed  www.shop.example.com
	// refused  www.example.com
	// refused  example.com
	// refused  shop.example.com.evil.test
}

// A certificate record can never be hidden behind Cloudflare's proxy.
//
// Cloudflare accepts the setting without complaint and then answers the name
// with addresses instead of the token, so issuance fails — or a renewal fails
// months later, silently, while the site is still serving. The plan is refused
// instead.
func ExampleNewSnapshot_refusesAProxiedValidationRecord() {
	_, err := dnsplan.NewSnapshot(dnsplan.KindPlatform, exampleTargetID, "example.com", []dnsplan.Record{
		{Type: "CNAME", Name: "account.example.com", Value: "connect.mirrorstack.ai", Proxied: true},
		{Type: "CNAME", Name: "_acme-challenge.account.example.com", Value: "abc123.dcv.cloudflare.com", Proxied: true},
	})
	fmt.Println(err)
	fmt.Println("is a plan-invalid refusal:", errors.Is(err, dnsplan.ErrPlanInvalid))
	// Output:
	// dnsplan: plan invalid: validation record is proxied: "_acme-challenge.account.example.com" is a certificate record and may not be proxied
	// is a plan-invalid refusal: true
}

// Only CNAME and TXT exist in the vocabulary.
//
// There is no way to express an A record, an MX record, an NS record or a CAA
// record in a plan, so no MirrorStack write can move your mail, delegate your
// zone, or change which authorities may issue for you.
func ExampleNormalizeRecords_acceptsOnlyCNAMEAndTXT() {
	for _, recordType := range []string{"CNAME", "TXT", "A", "AAAA", "MX", "NS", "CAA", "SRV"} {
		_, _, err := dnsplan.NormalizeRecords([]dnsplan.Record{
			{Type: recordType, Name: "account.example.com", Value: "connect.mirrorstack.ai"},
		})
		if err != nil {
			fmt.Printf("refused  %s\n", recordType)
			continue
		}
		fmt.Printf("accepted %s\n", recordType)
	}
	// Output:
	// accepted CNAME
	// accepted TXT
	// refused  A
	// refused  AAAA
	// refused  MX
	// refused  NS
	// refused  CAA
	// refused  SRV
}
