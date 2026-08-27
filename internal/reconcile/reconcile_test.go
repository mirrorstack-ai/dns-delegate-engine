package reconcile

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsplan"
	"github.com/mirrorstack-ai/dns-delegate-engine/internal/dnsprovider"
)

// fakeProvider records every call so a test can assert on the SEQUENCE of
// provider operations, not just the end state. Most of the rules this package
// exists to enforce are about ordering and about calls that must NOT happen.
type fakeProvider struct {
	zone string
	rows map[string][]dnsprovider.LiveRecord

	calls []string

	createErr  map[string]error
	patchErr   map[string]error
	duplicate  map[error]bool
	ambiguous  map[error]bool
	onCreate   func(dnsprovider.Desired)
	nextID     int
	listErr    error
	findErr    error
	listErrFor map[string]error
}

func newFake() *fakeProvider {
	return &fakeProvider{
		zone:       "zone1",
		rows:       map[string][]dnsprovider.LiveRecord{},
		createErr:  map[string]error{},
		patchErr:   map[string]error{},
		duplicate:  map[error]bool{},
		ambiguous:  map[error]bool{},
		listErrFor: map[string]error{},
	}
}

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) FindZone(_ context.Context, _, name string) (string, error) {
	f.calls = append(f.calls, "findzone:"+name)
	if f.findErr != nil {
		return "", f.findErr
	}
	return f.zone, nil
}

func (f *fakeProvider) ListRecordsAt(_ context.Context, _, _, name string) ([]dnsprovider.LiveRecord, error) {
	key := strings.ToLower(name)
	f.calls = append(f.calls, "list:"+key)
	if f.listErr != nil {
		return nil, f.listErr
	}
	if err := f.listErrFor[key]; err != nil {
		return nil, err
	}
	return f.rows[key], nil
}

func (f *fakeProvider) CreateRecord(_ context.Context, _, _ string, want dnsprovider.Desired) (string, error) {
	f.calls = append(f.calls, "create:"+want.Type+"|"+strings.ToLower(want.Name)+"|"+want.Value)
	if f.onCreate != nil {
		f.onCreate(want)
	}
	if err := f.createErr[want.Name]; err != nil {
		return "", err
	}
	f.nextID++
	id := fmt.Sprintf("id%d", f.nextID)
	key := strings.ToLower(want.Name)
	f.rows[key] = append(f.rows[key], dnsprovider.LiveRecord{
		ID: id, Type: want.Type, Name: want.Name, Value: want.Value, Proxied: want.Proxied,
	})
	return id, nil
}

func (f *fakeProvider) PatchRecord(_ context.Context, _, _, id string, want dnsprovider.Desired) error {
	f.calls = append(f.calls, "patch:"+id+"|"+want.Type+"|"+strings.ToLower(want.Name)+"|"+want.Value)
	if err := f.patchErr[want.Name]; err != nil {
		return err
	}
	key := strings.ToLower(want.Name)
	for i, row := range f.rows[key] {
		if row.ID == id {
			f.rows[key][i].Value = want.Value
			f.rows[key][i].Proxied = want.Proxied
		}
	}
	return nil
}

func (f *fakeProvider) SameValue(recordType, live, desired string) bool {
	if strings.EqualFold(recordType, "CNAME") {
		return strings.EqualFold(strings.TrimSuffix(live, "."), strings.TrimSuffix(desired, "."))
	}
	return live == desired
}

func (f *fakeProvider) IsDuplicate(err error) bool { return f.duplicate[err] }

func (f *fakeProvider) IsAmbiguous(err error) bool { return f.ambiguous[err] }

func (f *fakeProvider) countCalls(prefix string) int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

const anchor = "app.customer-owned.example"

func planOf(t *testing.T, records ...dnsplan.Record) dnsplan.Snapshot {
	t.Helper()
	s, err := dnsplan.NewSnapshot(dnsplan.KindPlatform,
		"3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607", anchor, records)
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return s
}

func fast(p dnsprovider.Provider) Publisher {
	return Publisher{Provider: p, Window: 2 * time.Second, ObserveTimeout: 200 * time.Millisecond, ObserveDelay: time.Millisecond}
}

// 🔴 The headline claim of this repository. A customer's other records at the
// same owner name — and at every other name — survive a publish untouched.
func TestPublishNeverRemovesAnything(t *testing.T) {
	f := newFake()
	f.rows[anchor] = []dnsprovider.LiveRecord{
		{ID: "cust1", Type: "TXT", Name: anchor, Value: "v=spf1 include:example.net ~all"},
		{ID: "cust2", Type: "TXT", Name: anchor, Value: "google-site-verification=abc"},
	}
	before := len(f.rows[anchor])

	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: true})
	if err := fast(f).Publish(context.Background(), "tok", plan); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := len(f.rows[anchor]); got != before+1 {
		t.Fatalf("want %d rows after adding one, got %d", before+1, got)
	}
	for _, want := range []string{"cust1", "cust2"} {
		found := false
		for _, row := range f.rows[anchor] {
			if row.ID == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("the customer's record %s was removed", want)
		}
	}
}

// Two distinct TXT values at one owner are two required records, not one record
// written twice. Collapsing them would drop a validation challenge.
func TestPublishPreservesMultipleTXTValuesAtOneOwner(t *testing.T) {
	f := newFake()
	plan := planOf(t,
		dnsplan.Record{Type: "TXT", Name: "_acme-challenge." + anchor, Value: "first"},
		dnsplan.Record{Type: "TXT", Name: "_acme-challenge." + anchor, Value: "second"},
	)
	if err := fast(f).Publish(context.Background(), "tok", plan); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := len(f.rows["_acme-challenge."+anchor]); got != 2 {
		t.Fatalf("want both TXT values, got %d", got)
	}
}

func TestPublishReadsEveryNameBeforeWritingAny(t *testing.T) {
	f := newFake()
	plan := planOf(t,
		dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: true},
		dnsplan.Record{Type: "TXT", Name: "_acme-challenge." + anchor, Value: "chal"},
	)
	if err := fast(f).Publish(context.Background(), "tok", plan); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	firstWrite := -1
	lastRead := -1
	for i, c := range f.calls {
		if strings.HasPrefix(c, "list:") {
			lastRead = i
		}
		if (strings.HasPrefix(c, "create:") || strings.HasPrefix(c, "patch:")) && firstWrite < 0 {
			firstWrite = i
		}
	}
	if firstWrite < 0 || lastRead > firstWrite {
		t.Fatalf("a read happened after the first write; calls=%v", f.calls)
	}
}

// 🔴 THE CUSTOMER'S OWN RECORD SURVIVES AUTHORIZATION. THIS IS THE PROMISE.
//
// This test used to assert the opposite — that an existing CNAME pointing
// somewhere else was patched to our target. It was, and a customer authorizing
// a domain took their own service off the air with no warning and no undo.
//
// We ADD. A name already answering with something that is not ours is refused,
// and the customer deletes it themselves and authorizes again.
func TestPublishRefusesToReplaceARecordThatIsNotOurs(t *testing.T) {
	f := newFake()
	f.rows[anchor] = []dnsprovider.LiveRecord{
		{ID: "theirs", Type: "CNAME", Name: anchor, Value: "their-live-service.example", Proxied: false},
	}
	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: true})

	err := fast(f).Publish(context.Background(), "tok", plan)
	if !errors.Is(err, ErrNameInUse) {
		t.Fatalf("want ErrNameInUse, got %v", err)
	}
	// It must NAME what is in the way — the customer has to know which record
	// to delete, and what it currently points at.
	if !strings.Contains(err.Error(), anchor) || !strings.Contains(err.Error(), "their-live-service.example") {
		t.Fatalf("the refusal must name the record and its value: %v", err)
	}
	if f.countCalls("patch:")+f.countCalls("create:") != 0 {
		t.Fatalf("NOTHING may be written; calls=%v", f.calls)
	}
	if len(f.rows[anchor]) != 1 || f.rows[anchor][0].Value != "their-live-service.example" {
		t.Fatalf("the customer's record must be untouched, got %#v", f.rows[anchor])
	}
}

// The in-place repair still exists, and is still needed: a record with OUR
// target but the wrong proxy state is ours, and is exactly what it is for.
func TestPublishStillRepairsOurOwnRecordInPlace(t *testing.T) {
	f := newFake()
	f.rows[anchor] = []dnsprovider.LiveRecord{
		{ID: "ours", Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: false},
	}
	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: true})
	if err := fast(f).Publish(context.Background(), "tok", plan); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if f.countCalls("create:") != 0 {
		t.Fatalf("must patch our own row, not create a second CNAME; calls=%v", f.calls)
	}
	if len(f.rows[anchor]) != 1 || f.rows[anchor][0].ID != "ours" || !f.rows[anchor][0].Proxied {
		t.Fatalf("want our row repaired in place, got %#v", f.rows[anchor])
	}
}

// Ours may not be the first row at that owner. Picking sameType[0] blindly
// would refuse a name we already hold.
func TestPublishFindsOurRecordAmongOthersAtTheSameOwner(t *testing.T) {
	f := newFake()
	f.rows[anchor] = []dnsprovider.LiveRecord{
		{ID: "stale", Type: "CNAME", Name: anchor, Value: "old-vendor.example", Proxied: false},
		{ID: "ours", Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: false},
	}
	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: true})
	if err := fast(f).Publish(context.Background(), "tok", plan); err != nil {
		t.Fatalf("our own record must still be repairable: %v", err)
	}
	if f.countCalls("patch:ours|") == 0 && f.countCalls("patch:ours") == 0 {
		t.Fatalf("the OURS row must be the one patched; calls=%v", f.calls)
	}
}

// 🔴 The proxy state is compared in BOTH directions. Testing row.Proxied alone
// encodes "grey is always right", and the reconciler would quietly turn off a
// routing record the console had just told the customer to proxy.
func TestPublishRepairsProxyStateInBothDirections(t *testing.T) {
	for _, tc := range []struct{ live, want bool }{{false, true}, {true, false}} {
		t.Run(fmt.Sprintf("live=%v want=%v", tc.live, tc.want), func(t *testing.T) {
			f := newFake()
			f.rows[anchor] = []dnsprovider.LiveRecord{
				{ID: "r", Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: tc.live},
			}
			plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: tc.want})
			if err := fast(f).Publish(context.Background(), "tok", plan); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			if f.countCalls("patch:") != 1 {
				t.Fatalf("a proxy-state mismatch must be repaired; calls=%v", f.calls)
			}
			if f.rows[anchor][0].Proxied != tc.want {
				t.Fatalf("proxy state not applied")
			}
		})
	}
}

func TestPublishIsIdempotent(t *testing.T) {
	f := newFake()
	f.rows[anchor] = []dnsprovider.LiveRecord{
		{ID: "r", Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai.", Proxied: true},
	}
	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: true})
	if err := fast(f).Publish(context.Background(), "tok", plan); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if f.countCalls("create:")+f.countCalls("patch:") != 0 {
		t.Fatalf("an already-correct record must not be rewritten; calls=%v", f.calls)
	}
}

// 🔴 An ambiguous write is resolved by READING. A retry is how one record
// becomes two.
func TestAmbiguousCreateObservesAndNeverRetriesTheWrite(t *testing.T) {
	f := newFake()
	boom := errors.New("504")
	f.ambiguous[boom] = true
	f.createErr[anchor] = boom
	// The write actually landed at the provider even though the response failed.
	f.onCreate = func(want dnsprovider.Desired) {
		f.rows[strings.ToLower(want.Name)] = []dnsprovider.LiveRecord{
			{ID: "landed", Type: want.Type, Name: want.Name, Value: want.Value, Proxied: want.Proxied},
		}
	}
	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: true})
	if err := fast(f).Publish(context.Background(), "tok", plan); err != nil {
		t.Fatalf("an observed-landed write must succeed: %v", err)
	}
	if got := f.countCalls("create:"); got != 1 {
		t.Fatalf("the write must be attempted exactly once, got %d; calls=%v", got, f.calls)
	}
	if f.countCalls("patch:") != 0 {
		t.Fatal("an ambiguous create must never be followed by a mutation")
	}
}

func TestAmbiguousCreateThatDidNotLandFails(t *testing.T) {
	f := newFake()
	boom := errors.New("500")
	f.ambiguous[boom] = true
	f.createErr[anchor] = boom
	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: true})
	err := fast(f).Publish(context.Background(), "tok", plan)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("want the original error, got %v", err)
	}
	if got := f.countCalls("create:"); got != 1 {
		t.Fatalf("the write must be attempted exactly once, got %d", got)
	}
}

// A duplicate response proves only that something raced us, never that the
// existing row is the one we wanted.
func TestDuplicateResponseStillVerifiesByReading(t *testing.T) {
	f := newFake()
	dup := errors.New("81057")
	f.duplicate[dup] = true
	f.createErr["_acme-challenge."+anchor] = dup
	// Something else wrote a DIFFERENT value at that owner.
	f.rows["_acme-challenge."+anchor] = []dnsprovider.LiveRecord{
		{ID: "other", Type: "TXT", Name: "_acme-challenge." + anchor, Value: "not-ours"},
	}
	plan := planOf(t, dnsplan.Record{Type: "TXT", Name: "_acme-challenge." + anchor, Value: "ours"})
	if err := fast(f).Publish(context.Background(), "tok", plan); err == nil {
		t.Fatal("a duplicate whose row is not the desired record must not be reported as success")
	}
}

// A definitive rejection is not observed and not retried: it is returned.
func TestDefinitiveRejectionIsReturnedImmediately(t *testing.T) {
	f := newFake()
	no := errors.New("400 invalid content")
	f.createErr[anchor] = no // neither duplicate nor ambiguous
	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: true})
	err := fast(f).Publish(context.Background(), "tok", plan)
	if !errors.Is(err, no) {
		t.Fatalf("want the provider error, got %v", err)
	}
	// One list before the write, and no observation reads after it.
	if got := f.countCalls("list:"); got != 1 {
		t.Fatalf("a definitive rejection must not be observed, got %d reads; calls=%v", got, f.calls)
	}
}

func TestPublishRefusesAnEscapingSnapshotBeforeTouchingTheProvider(t *testing.T) {
	f := newFake()
	// Bypass NewSnapshot to simulate a row written by a build without containment.
	plan := dnsplan.Snapshot{
		Version: dnsplan.Version, Kind: dnsplan.KindPlatform,
		TargetID: "3f2a1b4c-5d6e-4f70-8a91-b2c3d4e5f607", Anchor: anchor,
		Records:    []dnsplan.Record{{Type: "CNAME", Name: "www.customer-owned.example", Value: "edge.mirrorstack.ai"}},
		Identities: []string{"CNAME|www.customer-owned.example|edge.mirrorstack.ai"},
	}
	err := fast(f).Publish(context.Background(), "tok", plan)
	if !errors.Is(err, dnsplan.ErrAnchorEscape) {
		t.Fatalf("want ErrAnchorEscape, got %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("the provider must not be touched at all; calls=%v", f.calls)
	}
}

func TestPublishRefusesConflictingCNAMETargets(t *testing.T) {
	f := newFake()
	plan := planOf(t,
		dnsplan.Record{Type: "CNAME", Name: anchor, Value: "a.example"},
		dnsplan.Record{Type: "CNAME", Name: anchor, Value: "b.example"},
	)
	err := fast(f).Publish(context.Background(), "tok", plan)
	if !errors.Is(err, ErrConflictingPlan) {
		t.Fatalf("want ErrConflictingPlan, got %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("the provider must not be touched; calls=%v", f.calls)
	}
}

// A browser disconnect must not strand an arbitrary prefix of an approved plan.
func TestPublishSurvivesCallerCancellation(t *testing.T) {
	f := newFake()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai", Proxied: true})
	if err := fast(f).Publish(ctx, "tok", plan); err != nil {
		t.Fatalf("an already-cancelled caller must not abort the publish: %v", err)
	}
	if f.countCalls("create:") != 1 {
		t.Fatalf("the record must still be written; calls=%v", f.calls)
	}
}

func TestPublishRequiresATokenAndAProvider(t *testing.T) {
	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai"})
	if err := fast(newFake()).Publish(context.Background(), "  ", plan); err == nil {
		t.Fatal("an empty token must be refused")
	}
	if err := (Publisher{}).Publish(context.Background(), "tok", plan); err == nil {
		t.Fatal("a missing provider must be refused")
	}
	if err := fast(newFake()).Publish(context.Background(), "tok", dnsplan.Snapshot{Anchor: anchor}); !errors.Is(err, ErrNoRecords) {
		t.Fatal("an empty plan must be refused")
	}
}

func TestReadFailureAbortsBeforeAnyWrite(t *testing.T) {
	f := newFake()
	f.listErr = errors.New("transport")
	plan := planOf(t, dnsplan.Record{Type: "CNAME", Name: anchor, Value: "edge.mirrorstack.ai"})
	if err := fast(f).Publish(context.Background(), "tok", plan); err == nil {
		t.Fatal("a failed read must abort the publish")
	}
	if f.countCalls("create:")+f.countCalls("patch:") != 0 {
		t.Fatalf("nothing may be written after a failed read; calls=%v", f.calls)
	}
}
