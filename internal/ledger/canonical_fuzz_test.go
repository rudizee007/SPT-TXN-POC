package ledger

// Fuzz the canonical encoder — the function every adapter relies on to produce a
// deterministic, injective preimage for spt_txn_context_hash. The two invariants
// that matter for security: (1) it is deterministic, and (2) a value carrying a
// reserved separator byte (0x1f / 0x1e) is REJECTED, never silently accepted —
// otherwise an attacker could inject separators to make two different transfers
// collide to the same hash. Run:  go test ./internal/ledger/ -run x -fuzz FuzzCanonicalEncode

import "testing"

func hasSep(s string) bool {
	for _, c := range s {
		if c == 0x1f || c == 0x1e {
			return true
		}
	}
	return false
}

func FuzzCanonicalEncode(f *testing.F) {
	f.Add("XRP", "1000", "memo", "deadbeef")
	f.Add("US\x1fD", "1", "k", "v")     // separator in a field value
	f.Add("XRP", "1", "ke\x1ey", "v")   // separator in an extra key
	f.Fuzz(func(t *testing.T, cur, amt, ek, ev string) {
		ordered := [][2]string{{"chain", "xrpl"}, {"Amount", amt}, {"Currency", cur}}
		extra := map[string]string{ek: ev}

		b1, err1 := canonicalEncode(ordered, extra)
		b2, err2 := canonicalEncode(ordered, extra)

		// (1) Determinism: same input → same result (value and error).
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic error: %v vs %v", err1, err2)
		}
		if err1 == nil && string(b1) != string(b2) {
			t.Fatalf("non-deterministic output for identical input")
		}

		// (2) Reserved-separator handling is exact: reject iff a field carries one.
		anySep := hasSep(amt) || hasSep(cur) || hasSep(ek) || hasSep(ev)
		switch {
		case anySep && err1 == nil:
			t.Fatalf("a reserved separator slipped through unrejected (cur=%q amt=%q ek=%q ev=%q)", cur, amt, ek, ev)
		case !anySep && err1 != nil:
			t.Fatalf("clean input rejected: %v", err1)
		}
	})
}
