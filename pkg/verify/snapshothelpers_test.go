package verify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The snapshot body's on-disk shape, mirrored here so the tests exercise the
// FORMAT a producer emits rather than an internal Go type.
type testRecord struct {
	Iss        string    `json:"Iss"`
	Role       string    `json:"Role"`
	PublicKey  []byte    `json:"PublicKey"`
	KeyType    string    `json:"KeyType"`
	ValidFrom  time.Time `json:"ValidFrom"`
	ValidUntil time.Time `json:"ValidUntil"`
	Status     string    `json:"Status"`
}

type testBody struct {
	Version int           `json:"version"`
	Records []*testRecord `json:"records"`
}

func record(iss, role string, pub ed25519.PublicKey) *testRecord {
	return &testRecord{
		Iss: iss, Role: role, PublicKey: pub, KeyType: "Ed25519",
		ValidFrom:  time.Now().Add(-time.Hour).UTC().Truncate(time.Second),
		ValidUntil: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		Status:     "active",
	}
}

func seedRecords(t *testing.T) []*testRecord {
	t.Helper()
	ctPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ttsPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return []*testRecord{
		record("domain-a", "ct_issuer", ctPub),
		record("domain-a", "tts_issuer", ttsPub),
	}
}

func marshalBody(t *testing.T, recs []*testRecord) []byte {
	t.Helper()
	return marshal(t, testBody{Version: 1, Records: recs})
}

func writeBody(t *testing.T, recs []*testRecord) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "registry-snapshot.json")
	if err := os.WriteFile(p, marshalBody(t, recs), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
