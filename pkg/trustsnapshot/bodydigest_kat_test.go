package trustsnapshot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The body digest gets its own cross-language known-answer vectors, exactly as
// the signing input does (spec §5, last bullet). Without them the digest is
// agreement between this package and itself, and a Rust or TypeScript producer
// has nothing to hit.
//
// Regenerate deliberately, never to make a test pass:
//
//	SPT_UPDATE_KAT=1 go test ./pkg/trustsnapshot/ -run TestBodyDigestKAT
//
// It is an environment variable rather than a flag on purpose: a flag is easy to
// add to a failing command line, and this is not a command you should reach for
// when a test goes red. A changed golden is a FORMAT CHANGE. It invalidates every
// published snapshot and every pinned digest, so it needs a domain bump and a
// migration, not a commit.
var updateKAT = os.Getenv("SPT_UPDATE_KAT") == "1"

type katVector struct {
	Name              string          `json:"name"`
	Why               string          `json:"why"`
	Body              json.RawMessage `json:"body"`
	ExpectedCanonical string          `json:"expected_canonical"`
	ExpectedDigestHex string          `json:"expected_digest_hex"`
}

const katPath = "testdata/trust-snapshot-body-digest-v1.kat.json"

func TestBodyDigestKAT(t *testing.T) {
	vectors := []katVector{
		{
			Name: "empty record set",
			Why:  "a zero-record snapshot is a valid fail-closed fixture and must still digest deterministically",
			Body: json.RawMessage(`{"version":1,"records":[]}`),
		},
		{
			Name: "single ed25519 ct_issuer",
			Why:  "the ordinary case: key material hex-encoded, timestamps integer ms",
			Body: json.RawMessage(`{"version":1,"records":[{"Iss":"domain-a","Role":"ct_issuer","PublicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","KeyType":"Ed25519","ValidFrom":"2026-01-01T00:00:00Z","ValidUntil":"2027-01-01T00:00:00Z","Status":"active"}]}`),
		},
		{
			Name: "hybrid escrow record with an ML-KEM key",
			Why:  "the 1184-byte second key must be inside the digest too, or it can be swapped freely",
			Body: json.RawMessage(`{"version":1,"records":[{"Iss":"did:web:escrow.example","Role":"escrow","PublicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","MlkemEncapKey":"AQID","KeyType":"X25519-MLKEM768","ValidFrom":"2026-01-01T00:00:00Z","ValidUntil":"2027-01-01T00:00:00Z","Status":"active"}]}`),
		},
		{
			Name: "timestamps beyond 2^31 seconds",
			Why:  "millisecond timestamps past 2038 must stay integers and must not go through a float",
			Body: json.RawMessage(`{"version":1,"records":[{"Iss":"domain-a","Role":"tts_issuer","PublicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","KeyType":"Ed25519","ValidFrom":"2040-01-01T00:00:00Z","ValidUntil":"2099-12-31T23:59:59Z","Status":"active"}]}`),
		},
		{
			Name: "two records, order preserved",
			Why:  "JCS sorts object keys, not arrays: the record sequence is part of what is digested",
			Body: json.RawMessage(`{"version":1,"records":[{"Iss":"b","Role":"ct_issuer","PublicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","KeyType":"Ed25519","ValidFrom":"2026-01-01T00:00:00Z","ValidUntil":"2027-01-01T00:00:00Z","Status":"active"},{"Iss":"a","Role":"ct_issuer","PublicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","KeyType":"Ed25519","ValidFrom":"2026-01-01T00:00:00Z","ValidUntil":"2027-01-01T00:00:00Z","Status":"active"}]}`),
		},
	}

	for i := range vectors {
		v := &vectors[i]
		canonical, err := canonicalBodyBytes(v.Body)
		if err != nil {
			t.Fatalf("%s: canonicalize: %v", v.Name, err)
		}
		digest, err := BodyDigest(v.Body)
		if err != nil {
			t.Fatalf("%s: digest: %v", v.Name, err)
		}
		v.ExpectedCanonical = string(canonical)
		v.ExpectedDigestHex = digest
	}

	if updateKAT {
		raw, err := json.MarshalIndent(vectors, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(katPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(katPath, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("KAT regenerated at %s — this is a FORMAT CHANGE. Review the diff, "+
			"bump the domain if the bytes moved, and re-run without SPT_UPDATE_KAT.", katPath)
	}

	raw, err := os.ReadFile(katPath)
	if err != nil {
		t.Fatalf("read KAT: %v (regenerate with SPT_UPDATE_KAT=1 if this is the first run)", err)
	}
	var golden []katVector
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("parse KAT: %v", err)
	}
	if len(golden) != len(vectors) {
		t.Fatalf("KAT has %d vectors, the test defines %d", len(golden), len(vectors))
	}
	for i, want := range golden {
		got := vectors[i]
		if got.Name != want.Name {
			t.Fatalf("vector %d: name drifted: %q vs %q", i, got.Name, want.Name)
		}
		if got.ExpectedCanonical != want.ExpectedCanonical {
			t.Errorf("%s: canonical bytes changed\n got: %s\nwant: %s", want.Name, got.ExpectedCanonical, want.ExpectedCanonical)
		}
		if got.ExpectedDigestHex != want.ExpectedDigestHex {
			t.Errorf("%s: digest changed\n got: %s\nwant: %s", want.Name, got.ExpectedDigestHex, want.ExpectedDigestHex)
		}
	}
}

// The digest must change when key material changes. This is the property the
// whole body digest exists for: without it the signature proves only which ids
// and when, never what key material those ids map to.
func TestBodyDigest_CoversPublicKeyBytes(t *testing.T) {
	base := []byte(`{"version":1,"records":[{"Iss":"domain-a","Role":"ct_issuer","PublicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","KeyType":"Ed25519","ValidFrom":"2026-01-01T00:00:00Z","ValidUntil":"2027-01-01T00:00:00Z","Status":"active"}]}`)
	flipped := []byte(`{"version":1,"records":[{"Iss":"domain-a","Role":"ct_issuer","PublicKey":"AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","KeyType":"Ed25519","ValidFrom":"2026-01-01T00:00:00Z","ValidUntil":"2027-01-01T00:00:00Z","Status":"active"}]}`)

	a, err := BodyDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BodyDigest(flipped)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("one flipped public-key byte did not change the digest — the digest does not cover key material")
	}
}

// The version field must be inside the digested bytes. A format version protects
// against mis-parsing and authenticates nothing; outside the digest, an attacker
// flips it and the same bytes are reinterpreted under different parsing rules
// while the digest still matches.
func TestBodyDigest_CoversTheVersionField(t *testing.T) {
	v1 := []byte(`{"version":1,"records":[]}`)
	v2 := []byte(`{"version":2,"records":[]}`)
	a, err := BodyDigest(v1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BodyDigest(v2)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("changing version did not change the digest")
	}
}

// A pretty-printed body and a compact one are the same snapshot.
func TestBodyDigest_IsIndependentOfWhitespaceAndKeyOrder(t *testing.T) {
	compact := []byte(`{"version":1,"records":[{"Iss":"a","Role":"ct_issuer","PublicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","KeyType":"Ed25519","ValidFrom":"2026-01-01T00:00:00Z","ValidUntil":"2027-01-01T00:00:00Z","Status":"active"}]}`)
	pretty := []byte("\n  {\n  \"records\" : [ {\n    \"Status\": \"active\",\n    \"Iss\": \"a\",\n    \"Role\": \"ct_issuer\",\n    \"ValidUntil\": \"2027-01-01T00:00:00Z\",\n    \"ValidFrom\": \"2026-01-01T00:00:00Z\",\n    \"KeyType\": \"Ed25519\",\n    \"PublicKey\": \"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\"\n  } ],\n  \"version\": 1\n}")

	a, err := BodyDigest(compact)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BodyDigest(pretty)
	if err != nil {
		t.Fatalf("pretty-printed body: %v", err)
	}
	if a != b {
		t.Fatalf("whitespace or key order changed the digest:\n%s\n%s", a, b)
	}
}

// A body with a field this format does not define is refused rather than
// digested-and-ignored: an unknown field is either a newer format (which needs a
// version bump) or injected content, and neither should silently pass.
func TestBodyDigest_RefusesUnknownFields(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"records":[],"extra":"x"}`,
		`{"version":1,"records":[{"Iss":"a","Role":"ct_issuer","PublicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","KeyType":"Ed25519","ValidFrom":"2026-01-01T00:00:00Z","ValidUntil":"2027-01-01T00:00:00Z","Status":"active","Backdoor":true}]}`,
		`{"version":1,"records":[]} trailing`,
		`{"version":1,"records":[]}{"version":2,"records":[]}`,
	} {
		if _, err := BodyDigest([]byte(body)); err == nil {
			t.Errorf("accepted a body with unknown or trailing content: %s", body)
		}
	}
}
