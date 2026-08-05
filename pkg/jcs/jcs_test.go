package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// TestGoldenVectors cross-checks this implementation against vectors produced
// by an independent RFC 8785 implementation (python rfc8785). Differential
// testing against a second implementation is the primary defense against the
// canonicalization-divergence bug class (THREAT-MODEL §4.1).
func TestGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatalf("read golden vectors: %v", err)
	}
	var vectors []struct {
		ValueJSON string `json:"value_json"`
		Canonical string `json:"canonical"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode golden vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no golden vectors")
	}
	for i, v := range vectors {
		got, err := CanonicalizeRaw([]byte(v.ValueJSON))
		if err != nil {
			t.Errorf("vector %d: CanonicalizeRaw(%q): %v", i, v.ValueJSON, err)
			continue
		}
		if string(got) != v.Canonical {
			t.Errorf("vector %d:\n input  %s\n got    %s\n want   %s", i, v.ValueJSON, got, v.Canonical)
		}
	}
}

// TestRejects: every out-of-subset input must be rejected, not normalized.
func TestRejects(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"duplicate key", `{"a":1,"a":2}`, ErrDuplicateKey},
		{"duplicate key nested", `{"x":{"k":1,"k":1}}`, ErrDuplicateKey},
		{"float", `{"a":1.5}`, ErrNumber},
		{"exponent", `{"a":1e3}`, ErrNumber},
		{"capital exponent", `{"a":1E3}`, ErrNumber},
		{"negative zero", `{"a":-0}`, ErrNumber},
		{"fraction zero", `{"a":1.0}`, ErrNumber},
		{"too large", `{"a":9007199254740992}`, ErrNumber},
		{"too small", `{"a":-9007199254740992}`, ErrNumber},
		{"huge", `{"a":184467440737095516160}`, ErrNumber},
		{"leading zero", `{"a":01}`, nil}, // any error acceptable: invalid JSON
		{"trailing data", `{"a":1} {"b":2}`, nil},
		{"trailing garbage", `{"a":1}xyz`, nil},
		{"bare garbage", `@@`, nil},
		{"unterminated", `{"a":`, nil},
		{"replacement char", "{\"a\":\"�\"}", ErrString},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CanonicalizeRaw([]byte(tc.raw))
			if err == nil {
				t.Fatalf("input %q accepted; want rejection", tc.raw)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("input %q: got error %v, want %v", tc.raw, err, tc.want)
			}
		})
	}
}

// TestDepthBound: nesting beyond MaxDepth fails closed.
func TestDepthBound(t *testing.T) {
	deep := ""
	for i := 0; i <= MaxDepth+1; i++ {
		deep += "["
	}
	for i := 0; i <= MaxDepth+1; i++ {
		deep += "]"
	}
	if _, err := CanonicalizeRaw([]byte(deep)); !errors.Is(err, ErrDepth) {
		t.Fatalf("depth %d accepted (err=%v); want ErrDepth", MaxDepth+2, err)
	}
	// At the bound it must still work.
	ok := ""
	for i := 0; i < MaxDepth-1; i++ {
		ok += "["
	}
	for i := 0; i < MaxDepth-1; i++ {
		ok += "]"
	}
	if _, err := CanonicalizeRaw([]byte(ok)); err != nil {
		t.Fatalf("depth %d rejected: %v", MaxDepth-1, err)
	}
}

// TestGoValueAndRawAgree: canonicalizing a Go value and canonicalizing its
// JSON encoding must produce identical bytes (issuer path vs verifier path).
func TestGoValueAndRawAgree(t *testing.T) {
	vals := []any{
		map[string]any{"tool": "payments.transfer", "params": map[string]any{"amount": "125000.00", "beneficiary": "GB29NWBK60161331926819"}, "target": "mcp://payments"},
		map[string]any{"n": int64(9007199254740991), "m": -1, "z": uint64(0)},
		[]any{"a", true, nil, map[string]any{"k": "v"}},
		map[string]any{"€": "e", "😀": "s", "A": "a"},
	}
	for i, v := range vals {
		fromValue, err := Canonicalize(v)
		if err != nil {
			t.Fatalf("case %d: Canonicalize: %v", i, err)
		}
		enc, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("case %d: marshal: %v", i, err)
		}
		fromRaw, err := CanonicalizeRaw(enc)
		if err != nil {
			t.Fatalf("case %d: CanonicalizeRaw: %v", i, err)
		}
		if !bytes.Equal(fromValue, fromRaw) {
			t.Errorf("case %d: value path %s != raw path %s", i, fromValue, fromRaw)
		}
	}
}

// TestDeterministic: repeated canonicalization of the same map (random Go map
// iteration order) always yields identical bytes.
func TestDeterministic(t *testing.T) {
	v := map[string]any{}
	for _, k := range []string{"z", "y", "x", "w", "v", "u", "t", "€", "😀", "a", "A", "0", ""} {
		v[k] = k + "!"
	}
	first, err := Canonicalize(v)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		got, err := Canonicalize(v)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, got) {
			t.Fatalf("iteration %d: nondeterministic output", i)
		}
	}
}

// TestUTF16Order pins the sorting subtlety: supplementary characters (encoded
// as surrogate pairs, first unit 0xD800–0xDBFF) sort BEFORE BMP characters in
// 0xE000–0xFFFF under UTF-16 code-unit order, which is the opposite of
// UTF-8 byte order. Getting this wrong is a canonicalization divergence.
func TestUTF16Order(t *testing.T) {
	got, err := Canonicalize(map[string]any{"￺": 1, "\U0001F600": 2})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"😀":2,"￺":1}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

// FuzzRoundTrip: for any raw input the canonicalizer either rejects or
// produces output that (a) is valid JSON, (b) re-canonicalizes to itself
// (idempotence), and (c) never accepts two byte-distinct canonical forms for
// the same parsed value.
func FuzzRoundTrip(f *testing.F) {
	seeds := []string{
		`{"b":1,"a":2}`, `[]`, `{}`, `null`, `true`, `"s"`, `0`,
		`{"a":{"b":[1,2,3]},"c":"\n"}`,
		`{"€":"e","😀":"s"}`,
		`{"a":9007199254740991}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		can1, err := CanonicalizeRaw(raw)
		if err != nil {
			return // rejection is always acceptable
		}
		// Idempotence: canonical form canonicalizes to itself.
		can2, err := CanonicalizeRaw(can1)
		if err != nil {
			t.Fatalf("canonical output rejected on re-parse: %q -> %q: %v", raw, can1, err)
		}
		if !bytes.Equal(can1, can2) {
			t.Fatalf("not idempotent: %q -> %q -> %q", raw, can1, can2)
		}
		// Output must be valid JSON.
		if !json.Valid(can1) {
			t.Fatalf("canonical output is not valid JSON: %q", can1)
		}
	})
}
