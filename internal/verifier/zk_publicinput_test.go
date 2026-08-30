package verifier

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// The ceiling becomes a uint64 public input to the ZK chain proof, and that
// conversion is the ONLY thing binding the proof to the presented leaf's
// ceiling. Go's float-to-unsigned conversion is implementation-defined out of
// range — a wei-scale ceiling above 2^64 yields 2^63 on amd64 and saturates on
// arm64, so every large ceiling collapses onto one constant and a proof for a
// legitimately attenuated chain would verify against a much larger presented
// one. Refusing is the only answer that means the same thing on both machines.
func TestUint64Ceiling_RefusesEverythingTheConversionCannotCarry(t *testing.T) {
	cases := map[string]any{
		"above 2^64 (20 ETH in wei)": 2e19,
		"far above 2^64 (1 NEAR)":    1e24,
		"exactly 2^64":               math.Pow(2, 64),
		"negative":                   -1.0,
		"negative int":               -1,
		"fractional":                 5000.75,
		"NaN":                        math.NaN(),
		"positive infinity":          math.Inf(1),
		"negative infinity":          math.Inf(-1),
		"string":                     "5000",
		"bool":                       true,
		"object":                     map[string]any{"x": 1},
		"list":                       []any{1},
		"missing":                    nil,
		"json.Number hex":            json.Number("0x2710"),
		"json.Number exponent":       json.Number("1e6"),
		"json.Number negative":       json.Number("-1"),
		"json.Number above 2^64":     json.Number("18446744073709551616"),
		"json.Number fractional":     json.Number("5000.75"),
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := uint64Ceiling(v)
			if err == nil {
				t.Fatalf("accepted %v as a public input and produced %d", v, got)
			}
		})
	}
}

// And it must not over-deny: every ceiling that genuinely fits converts exactly.
func TestUint64Ceiling_AcceptsWhatFitsExactly(t *testing.T) {
	cases := map[string]struct {
		in   any
		want uint64
	}{
		"small float":            {5000.0, 5000},
		"zero is the narrowest":  {0.0, 0},
		"int":                    {5000, 5000},
		"int64":                  {int64(5000), 5000},
		"uint64":                 {uint64(5000), 5000},
		"json.Number":            {json.Number("5000"), 5000},
		"json.Number at 2^63":    {json.Number("9223372036854775808"), 1 << 63},
		"json.Number at 2^64-1":  {json.Number("18446744073709551615"), math.MaxUint64},
		"float above 2^53 exact": {float64(1 << 60), 1 << 60},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := uint64Ceiling(c.in)
			if err != nil {
				t.Fatalf("a ceiling that fits was refused: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %d want %d", got, c.want)
			}
		})
	}
}

// Property: nothing that is accepted may differ from the exact value of the
// input. This is what makes the public input a faithful binding rather than a
// lossy summary — it is the whole reason the conversion is guarded.
func TestProperty_AcceptedCeilingsConvertExactly(t *testing.T) {
	accepted, refused := 0, 0
	for _, digits := range []string{
		"1", "2", "1000", "5000", "9007199254740993", "9223372036854775807",
		"9223372036854775808", "18446744073709551615", "18446744073709551616",
		"0", "-1", "-18446744073709551616",
	} {
		n := json.Number(digits)
		got, err := uint64Ceiling(n)
		if err != nil {
			refused++
			continue
		}
		accepted++
		if json.Number(uint64ToString(got)) != n {
			t.Fatalf("accepted %q but converted it to %d", digits, got)
		}
	}
	t.Logf("denominator: %d accepted and %d refused ceilings exercised", accepted, refused)
	if accepted == 0 || refused == 0 {
		t.Fatal("the table did not exercise both outcomes; the test proves nothing")
	}
}

func uint64ToString(u uint64) string {
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

// intClaim converts a JSON number claim to int64. int64(f) is
// implementation-defined out of range: an exp of 1e30 becomes -2^63 on amd64
// (reads as long expired, safe) and saturates to +2^63-1 on arm64 (reads as
// valid for the next 292 billion years, NOT safe). A claim that cannot be
// represented must fail closed on both machines.
func TestIntClaim_RefusesValuesItCannotRepresent(t *testing.T) {
	for name, v := range map[string]any{
		"far above int64":   1e30,
		"far below int64":   -1e30,
		"exactly 2^63":      math.Pow(2, 63),
		"NaN":               math.NaN(),
		"positive infinity": math.Inf(1),
		"negative infinity": math.Inf(-1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := intClaim(map[string]any{"exp": v}, "exp"); ok {
				t.Fatalf("accepted %v and produced %d", v, got)
			}
		})
	}
}

func TestIntClaim_AcceptsRepresentableValues(t *testing.T) {
	for name, c := range map[string]struct {
		in   float64
		want int64
	}{
		"a timestamp": {1750000000, 1750000000},
		"zero":        {0, 0},
		"negative":    {-1, -1},
		"2^53":        {math.Pow(2, 53), 1 << 53},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := intClaim(map[string]any{"exp": c.in}, "exp")
			if !ok {
				t.Fatal("a representable value was refused")
			}
			if got != c.want {
				t.Fatalf("got %d want %d", got, c.want)
			}
		})
	}
}

// The delegation-depth budget is a uint64 public input too, and int64(-1)
// converts to a well-defined 2^64-1 — so without a range check a negative budget
// makes the proof's depth bound meaningless instead of refusing it.
func TestUint64Depth_RefusesANonPositiveBudget(t *testing.T) {
	for _, n := range []int64{0, -1, -1000, math.MinInt64} {
		if got, err := uint64Depth(n); err == nil {
			t.Fatalf("accepted a budget of %d and produced %d", n, got)
		}
	}
}

func TestUint64Depth_AcceptsAPositiveBudget(t *testing.T) {
	for _, n := range []int64{1, 3, 1 << 40, math.MaxInt64} {
		got, err := uint64Depth(n)
		if err != nil {
			t.Fatalf("a budget of %d was refused: %v", n, err)
		}
		if got != uint64(n) {
			t.Fatalf("got %d want %d", got, n)
		}
	}
}

// The effective scope is the intersection over the whole chain, and a hop must
// not be able to shed a constraint by dropping a key INSIDE a nested object.
// A shallow overlay replaced the whole object with the hop's version, which is
// the same dropped-dimension widening the chain intersection exists to defeat —
// one level down, where the block comment claimed it was already handled.
func TestOverlayScope_RetainsDimensionsDroppedInsideANestedObject(t *testing.T) {
	effective := tbac.Scope{
		"currency":   "USD",
		"max_amount": 5000,
		"limits":     map[string]any{"max": 100, "currency": "USD"},
		"region":     map[string]any{"tier": 2, "zone": "z1"},
	}
	// The hop keeps `limits` but drops `max` from inside it, and drops `region`
	// entirely. Neither may loosen anything.
	hop := tbac.Scope{
		"currency":   "USD",
		"max_amount": 4000,
		"limits":     map[string]any{"currency": "USD"},
	}
	overlayScope(effective, hop)

	if effective["max_amount"] != 4000 {
		t.Fatalf("the hop's tighter ceiling was not applied: %v", effective["max_amount"])
	}
	limits, ok := effective["limits"].(map[string]any)
	if !ok {
		t.Fatalf("limits came back as %T", effective["limits"])
	}
	if limits["max"] != 100 {
		t.Fatalf("a bound dropped INSIDE a nested object was discarded: %v", limits)
	}
	region, ok := effective["region"].(map[string]any)
	if !ok || region["tier"] != 2 || region["zone"] != "z1" {
		t.Fatalf("a nested object the hop dropped entirely was not retained: %v", effective["region"])
	}
}

// And the overlay must still tighten where the hop does declare a value,
// including inside an object — retaining is not the same as ignoring.
func TestOverlayScope_StillTightensInsideANestedObject(t *testing.T) {
	effective := tbac.Scope{"limits": map[string]any{"max": 100, "currency": "USD"}}
	overlayScope(effective, tbac.Scope{"limits": map[string]any{"max": 10}})

	limits := effective["limits"].(map[string]any)
	if limits["max"] != 10 {
		t.Fatalf("the hop's tighter nested bound was not applied: %v", limits)
	}
	if limits["currency"] != "USD" {
		t.Fatalf("the retained sibling was lost: %v", limits)
	}
}
