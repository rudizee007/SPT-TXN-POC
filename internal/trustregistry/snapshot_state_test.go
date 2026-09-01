package trustregistry

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/pkg/trustsnapshot"
)

// signAt signs body as snapshot `id` issued at `at`, writing the manifest
// beside bodyPath, and returns the manifest path.
func signAt(t *testing.T, bodyPath string, body []byte, ids []string, id string, at time.Time, prev *string, priv ed25519.PrivateKey) string {
	t.Helper()
	m, err := trustsnapshot.Sign(body, id, at, ids, prev, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := trustsnapshot.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	mp := ManifestPathFor(bodyPath)
	if err := os.WriteFile(mp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return mp
}

// Two signed snapshots of the same registry: S1 with an issuer, S2 issued
// later with that issuer revoked. Returns the body/manifest writers so a test
// can put either pair on disk.
type twoSnapshots struct {
	bodyPath string
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	ids      []string
	s1, s2   []byte
	t1, t2   time.Time
}

func buildTwoSnapshots(t *testing.T) *twoSnapshots {
	t.Helper()
	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "registry.json")
	reg := seed(t, bodyPath)
	s1, err := reg.ExportBody()
	if err != nil {
		t.Fatal(err)
	}
	ids := reg.IssuerIDs()
	recs, err := reg.List(context.Background(), RoleCTIssuer)
	if err != nil || len(recs) == 0 {
		t.Fatalf("seed has no ct_issuer: %v", err)
	}
	if err := reg.Revoke(context.Background(), recs[0].Iss, RoleCTIssuer, time.Now()); err != nil {
		t.Fatal(err)
	}
	s2, err := reg.ExportBody()
	if err != nil {
		t.Fatal(err)
	}
	_ = reg.Close()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	return &twoSnapshots{bodyPath: bodyPath, pub: pub, priv: priv, ids: ids,
		s1: s1, s2: s2, t1: now.Add(-2 * time.Hour), t2: now.Add(-time.Hour)}
}

func (w *twoSnapshots) put(t *testing.T, which int) {
	t.Helper()
	body, id, at := w.s1, "snap-1", w.t1
	var prev *string
	if which == 2 {
		body, id, at = w.s2, "snap-2", w.t2
		p := "snap-1"
		prev = &p
	}
	if err := os.WriteFile(w.bodyPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	signAt(t, w.bodyPath, body, w.ids, id, at, prev, w.priv)
}

func (w *twoSnapshots) open(t *testing.T, state trustsnapshot.StateStore) (*PersistentRegistry, error) {
	t.Helper()
	return OpenVerified(ManifestPathFor(w.bodyPath), w.bodyPath, trustsnapshot.Options{
		PinnedKeys: []ed25519.PublicKey{w.pub}, MaxAge: 24 * time.Hour, State: state,
	})
}

// With an acceptance record, a validly signed snapshot older than the last one
// accepted is refused; the same snapshot loads again (a restart); a newer one
// loads and advances the record.
func TestOpenVerified_StateRefusesAnOlderSnapshot(t *testing.T) {
	w := buildTwoSnapshots(t)
	state := trustsnapshot.FileState{Path: filepath.Join(t.TempDir(), "accepted.json")}
	issuer := w.ids[0]

	w.put(t, 2)
	reg, err := w.open(t, state)
	if err != nil {
		t.Fatalf("S2: %v", err)
	}
	if _, err := reg.Lookup(context.Background(), issuer, RoleCTIssuer); !errors.Is(err, ErrNotFound) {
		t.Fatalf("S2 should have the issuer revoked, got %v", err)
	}

	// Restart on the same snapshot: fine.
	if _, err := w.open(t, state); err != nil {
		t.Fatalf("reloading the accepted snapshot refused: %v", err)
	}

	// S1 restored on disk: valid signature, older issued_ms.
	w.put(t, 1)
	if _, err := w.open(t, state); !errors.Is(err, trustsnapshot.ErrRollback) {
		t.Fatalf("an older signed snapshot loaded after a newer one was accepted: %v", err)
	}

	// Without a record there is nothing to compare against, and it loads —
	// which is why long-running readers set State.
	if _, err := w.open(t, nil); err != nil {
		t.Fatalf("no state: expected the older snapshot to load, got %v", err)
	}
}

// The record is written on first acceptance and only advanced by a newer
// snapshot; a store that cannot be written refuses the load.
func TestOpenVerified_StateIsRecordedAndUnwritableStateRefuses(t *testing.T) {
	w := buildTwoSnapshots(t)
	path := filepath.Join(t.TempDir(), "accepted.json")
	state := trustsnapshot.FileState{Path: path}
	w.put(t, 1)
	if _, err := w.open(t, state); err != nil {
		t.Fatal(err)
	}
	st, found, err := state.Load()
	if err != nil || !found || st.ID != "snap-1" {
		t.Fatalf("record after first load: %+v found=%v err=%v", st, found, err)
	}
	w.put(t, 2)
	if _, err := w.open(t, state); err != nil {
		t.Fatal(err)
	}
	st, _, _ = state.Load()
	if st.ID != "snap-2" {
		t.Fatalf("record did not advance: %+v", st)
	}

	// A malformed record is an error, never "nothing accepted yet".
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.open(t, state); !errors.Is(err, trustsnapshot.ErrState) {
		t.Fatalf("malformed record: got %v", err)
	}
}

// A snapshot issued ahead of the clock beyond the tolerance is refused; it
// would otherwise never age.
func TestOpenVerified_RefusesAFutureDatedSnapshot(t *testing.T) {
	w := buildTwoSnapshots(t)
	if err := os.WriteFile(w.bodyPath, w.s1, 0o600); err != nil {
		t.Fatal(err)
	}
	signAt(t, w.bodyPath, w.s1, w.ids, "snap-f", time.Now().Add(time.Hour), nil, w.priv)
	if _, err := w.open(t, nil); !errors.Is(err, trustsnapshot.ErrFuture) {
		t.Fatalf("future-dated snapshot: got %v", err)
	}
}

// Staleness is a property of the running process, not of the open call: once
// the snapshot's issued_ms + max_age has passed, Lookup and List refuse.
func TestLookup_RefusesOnceTheSnapshotIsPastMaxAge(t *testing.T) {
	w := buildTwoSnapshots(t)
	w.put(t, 1) // issued two hours ago
	reg, err := OpenVerified(ManifestPathFor(w.bodyPath), w.bodyPath, trustsnapshot.Options{
		PinnedKeys: []ed25519.PublicKey{w.pub},
		MaxAge:     2*time.Hour + 500*time.Millisecond, // fresh now, stale in half a second
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Lookup(context.Background(), w.ids[0], RoleCTIssuer); err != nil {
		t.Fatalf("fresh lookup: %v", err)
	}
	time.Sleep(700 * time.Millisecond)
	if _, err := reg.Lookup(context.Background(), w.ids[0], RoleCTIssuer); !errors.Is(err, ErrSnapshotStale) {
		t.Fatalf("stale lookup: got %v", err)
	}
	if _, err := reg.List(context.Background(), RoleCTIssuer); !errors.Is(err, ErrSnapshotStale) {
		t.Fatalf("stale list: got %v", err)
	}

	// AllowStale is the explicit degrade mode and lifts the bound.
	w.put(t, 1)
	reg2, err := OpenVerified(ManifestPathFor(w.bodyPath), w.bodyPath, trustsnapshot.Options{
		PinnedKeys: []ed25519.PublicKey{w.pub}, MaxAge: time.Second, AllowStale: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg2.Lookup(context.Background(), w.ids[0], RoleCTIssuer); err != nil {
		t.Fatalf("AllowStale lookup: %v", err)
	}
	if reg2.Manifest() == nil || reg2.Manifest().ID != "snap-1" {
		t.Fatalf("manifest not retained: %+v", reg2.Manifest())
	}
}
