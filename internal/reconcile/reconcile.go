// Package reconcile publishes a contained plan into a customer's zone.
//
// 🔴 EVERY SAFETY RULE LIVES HERE, ABOVE THE PROVIDER INTERFACE.
//
// An adapter supplies transport and vocabulary; it cannot opt out of a rule it
// never sees. The rules are:
//
//  1. Never delete. There is no delete call, here or in the interface.
//  2. Read every affected owner name BEFORE writing any of them, so create-vs-
//     update is decided against a coherent read.
//  3. Update a routing CNAME in place rather than adding a second one.
//  4. Never retry an ambiguous write. Re-read instead, within a bounded window.
//  5. Do all of it inside one bounded window, detached from the caller's
//     cancellation — a browser disconnect must not strand an arbitrary prefix of
//     an approved plan.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsprovider"
)

const (
	// DefaultWindow bounds the whole publication. Once the provider has
	// exchanged the short-lived grant, a browser disconnect must not strand an
	// arbitrary prefix of the reviewed plan — but it must not run forever either.
	DefaultWindow = 45 * time.Second
	// DefaultObserveTimeout bounds ONE ambiguous write's read-only recheck.
	DefaultObserveTimeout = 10 * time.Second
	// DefaultObserveDelay is the pause between observation reads.
	DefaultObserveDelay = 200 * time.Millisecond
)

// ErrNoRecords means the plan handed us nothing to reconcile. It is a caller
// bug or a stale row, never something to retry.
var ErrNoRecords = errors.New("reconcile: no DNS records to publish")

// ErrConflictingPlan means the plan cannot converge: two different CNAME targets
// at one owner name. Without this check a retry could alternate the single
// provider CNAME between targets and report success after satisfying only the
// last record in the plan.
var ErrConflictingPlan = errors.New("reconcile: plan contains conflicting CNAME targets")

// Publisher reconciles plans through one provider.
type Publisher struct {
	Provider dnsprovider.Provider

	// Window, ObserveTimeout and ObserveDelay default to the constants above.
	Window         time.Duration
	ObserveTimeout time.Duration
	ObserveDelay   time.Duration
}

func (p Publisher) window() time.Duration {
	if p.Window > 0 {
		return p.Window
	}
	return DefaultWindow
}

func (p Publisher) observeTimeout() time.Duration {
	if p.ObserveTimeout > 0 {
		return p.ObserveTimeout
	}
	return DefaultObserveTimeout
}

func (p Publisher) observeDelay() time.Duration {
	if p.ObserveDelay > 0 {
		return p.ObserveDelay
	}
	return DefaultObserveDelay
}

// Publish reconciles the snapshot's records into the customer's zone.
//
// It takes a dnsplan.Snapshot rather than a bare record slice so a caller cannot
// reach this code with a set that never passed anchor containment.
func (p Publisher) Publish(ctx context.Context, token string, snapshot dnsplan.Snapshot) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("reconcile: a provider token is required")
	}
	if p.Provider == nil {
		return fmt.Errorf("reconcile: no provider configured")
	}
	desired := snapshot.Records
	if len(desired) == 0 {
		return ErrNoRecords
	}
	// Containment is re-checked here, not assumed. Publish is the last place a
	// record can be stopped, and a snapshot can arrive from storage.
	for _, record := range desired {
		if !dnsplan.Contains(snapshot.Anchor, record.Name) {
			return fmt.Errorf("%w: %q is not at or under %q",
				dnsplan.ErrAnchorEscape, dnsplan.NormalizeName(record.Name), snapshot.Anchor)
		}
	}
	if err := validateNoConflictingCNAMEs(desired); err != nil {
		return err
	}

	// context.WithoutCancel, then a fresh deadline: the caller's cancellation
	// (a browser disconnect) must not abandon a half-published plan, but the
	// window must still close.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.window())
	defer cancel()

	zoneID, err := p.Provider.FindZone(ctx, token, desired[0].Name)
	if err != nil {
		return err
	}

	// Read every affected name before writing anything, so reconciliation is
	// idempotent and an existing CNAME can be updated in place. Do not invent a
	// local coexistence policy: providers permit apex CNAME flattening beside
	// records such as MX/TXT, and the provider API is the authoritative conflict
	// check.
	existing := make(map[string][]dnsprovider.LiveRecord, len(desired))
	for _, record := range desired {
		key := dnsplan.NormalizeName(record.Name)
		if _, ok := existing[key]; ok {
			continue
		}
		rows, err := p.Provider.ListRecordsAt(ctx, token, zoneID, record.Name)
		if err != nil {
			return err
		}
		existing[key] = rows
	}

	for _, record := range desired {
		want := dnsprovider.DesiredFrom(record)
		rows := existing[dnsplan.NormalizeName(record.Name)]

		var sameType []dnsprovider.LiveRecord
		matched := false
		for _, row := range rows {
			if !strings.EqualFold(strings.TrimSpace(row.Type), want.Type) {
				continue
			}
			sameType = append(sameType, row)
			if !p.Provider.SameValue(want.Type, row.Value, want.Value) {
				continue
			}
			// Value alone is not enough for a routing CNAME: a record with the
			// right target but the WRONG proxy state is still misconfigured, and
			// short-circuiting here is why a reconciler could never self-heal an
			// already-connected domain.
			//
			// 🔴 Compared in BOTH directions, deliberately. Testing `row.Proxied`
			// alone encodes "grey is always right", so the reconciler would take a
			// routing record the console had just told the customer to proxy and
			// quietly turn it back off.
			if want.Type == "CNAME" && row.Proxied != want.Proxied {
				continue
			}
			matched = true
		}
		if matched {
			continue
		}

		// A CNAME is updated in place when one already exists at this owner.
		// Creating a second one would leave the customer serving from whichever
		// the provider picked.
		if want.Type == "CNAME" && len(sameType) > 0 {
			if err := p.patchObserved(ctx, token, zoneID, sameType[0].ID, want); err != nil {
				return err
			}
			continue
		}
		if err := p.createObserved(ctx, token, zoneID, want); err != nil {
			return err
		}
	}
	return nil
}

// createObserved accepts an ambiguous provider result only when a bounded,
// read-only recheck proves the approved record exists. It never retries the
// write: the customer may have edited the owner after the provider applied (or
// rejected) the request, and no provider in scope exposes a version token with
// which a second mutation could be made conditional.
func (p Publisher) createObserved(ctx context.Context, token, zoneID string, want dnsprovider.Desired) error {
	_, err := p.Provider.CreateRecord(ctx, token, zoneID, want)
	if err == nil {
		return nil
	}
	duplicate := p.Provider.IsDuplicate(err)
	if !duplicate && !p.Provider.IsAmbiguous(err) {
		return err
	}
	matched, observeErr := p.observe(ctx, token, zoneID, "", want)
	if observeErr != nil {
		return fmt.Errorf("%w: observe ambiguous create: %w", err, observeErr)
	}
	if matched {
		return nil
	}
	if duplicate {
		return fmt.Errorf("%w: duplicate response did not expose the desired record", err)
	}
	return fmt.Errorf("%w: ambiguous create did not converge to the desired record", err)
}

// patchObserved has the same read-only ambiguity rule as createObserved. The id
// must still expose the desired route: a different row at the same owner is not
// evidence that this update landed.
func (p Publisher) patchObserved(ctx context.Context, token, zoneID, id string, want dnsprovider.Desired) error {
	err := p.Provider.PatchRecord(ctx, token, zoneID, id, want)
	if err == nil {
		return nil
	}
	if !p.Provider.IsAmbiguous(err) {
		return err
	}
	matched, observeErr := p.observe(ctx, token, zoneID, id, want)
	if observeErr != nil {
		return fmt.Errorf("%w: observe ambiguous update: %w", err, observeErr)
	}
	if matched {
		return nil
	}
	return fmt.Errorf("%w: ambiguous update did not converge to the desired record", err)
}

// observe re-reads until the desired record appears or the window closes.
//
// parent already carries the ONE publication deadline. Stripping it again would
// let every ambiguous write add a fresh observation window and exceed the
// approved operation's global bound.
func (p Publisher) observe(
	parent context.Context, token, zoneID, id string, want dnsprovider.Desired,
) (bool, error) {
	ctx, cancel := context.WithTimeout(parent, p.observeTimeout())
	defer cancel()
	var lastErr error
	for {
		rows, err := p.Provider.ListRecordsAt(ctx, token, zoneID, want.Name)
		if err == nil {
			lastErr = nil
			for _, row := range rows {
				if (id == "" || row.ID == id) && p.satisfies(row, want) {
					return true, nil
				}
			}
		} else {
			lastErr = err
		}
		if err := sleep(ctx, p.observeDelay()); err != nil {
			// Report the global deadline distinctly when it wins; otherwise
			// exhausting the local observation window is an ordinary
			// non-convergence result unless the final read itself failed.
			if parentErr := parent.Err(); parentErr != nil {
				return false, parentErr
			}
			if lastErr != nil {
				return false, lastErr
			}
			return false, nil
		}
	}
}

func (p Publisher) satisfies(row dnsprovider.LiveRecord, want dnsprovider.Desired) bool {
	return strings.EqualFold(strings.TrimSpace(row.Type), strings.TrimSpace(want.Type)) &&
		dnsplan.NormalizeName(row.Name) == dnsplan.NormalizeName(want.Name) &&
		p.Provider.SameValue(strings.ToUpper(strings.TrimSpace(want.Type)), row.Value, want.Value) &&
		row.Proxied == want.Proxied
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// validateNoConflictingCNAMEs rejects an approved plan that cannot converge.
// Multiple TXT values at one owner are valid and intentionally preserved;
// multiple distinct CNAME targets are not.
func validateNoConflictingCNAMEs(records []dnsplan.Record) error {
	targets := make(map[string]string, len(records))
	for _, record := range records {
		if !strings.EqualFold(record.Type, "CNAME") {
			continue
		}
		name := dnsplan.NormalizeName(record.Name)
		target := dnsplan.NormalizeName(record.Value)
		if previous, ok := targets[name]; ok && previous != target {
			return fmt.Errorf("%w: %q", ErrConflictingPlan, name)
		}
		targets[name] = target
	}
	return nil
}
