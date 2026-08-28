package ledger

import (
	"errors"
	"math/big"
	"testing"
)

func TestParseAmount_AcceptsCanonicalDecimals(t *testing.T) {
	cases := map[string]string{
		"integer":                  "5000",
		"one":                      "1",
		"fraction":                 "0.5",
		"trailing zeros are money": "5.00",
		"many decimals":            "0.000001",
		"large integer":            "18446744073709551616",
		"beyond float64 exact":     "9007199254740993",
		"xrp drops":                "100000000000000000",
		"long fraction":            "1.23456789012345678901234567890",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := ParseAmount(s)
			if err != nil {
				t.Fatalf("a canonical decimal was refused: %v", err)
			}
			// The value must be exact, not float-rounded.
			want, ok := new(big.Rat).SetString(s)
			if !ok || r.Cmp(want) != 0 {
				t.Fatalf("value not exact: got %v want %v", r, want)
			}
		})
	}
}

// The grammar is deliberately much narrower than big.Rat's. Every input here
// parses fine as a big.Rat and must NOT be accepted as an amount.
func TestParseAmount_RejectsTheWiderBigRatGrammar(t *testing.T) {
	cases := map[string]string{
		"fraction form": "1/3",
		"hexadecimal":   "0x2710",
		"binary":        "0b1010",
		"octal":         "0o17",
		"octal legacy":  "0177",
		"exponent":      "1e6",
		"exponent caps": "1E6",
		"binary exp":    "0x1p4",
		"explicit plus": "+5000",
		"underscores":   "1_000",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok := new(big.Rat).SetString(s); !ok {
				t.Skipf("%q is not accepted by big.Rat either, so it proves nothing here", s)
			}
			_, err := ParseAmount(s)
			if err == nil {
				t.Fatalf("%q was accepted as an amount", s)
			}
			if !errors.Is(err, ErrAmountGrammar) {
				t.Errorf("wrong diagnosis: want ErrAmountGrammar, got: %v", err)
			}
		})
	}
}

func TestParseAmount_RejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"leading zero":       "007",
		"leading zeros only": "00",
		"bare point":         ".",
		"no integer part":    ".5",
		"no fraction digits": "5.",
		"two points":         "1.2.3",
		"leading space":      " 5000",
		"trailing space":     "5000 ",
		"inner space":        "5 000",
		"thousands comma":    "5,000",
		"nan":                "NaN",
		"inf":                "Inf",
		"unicode digits":     "５０００",
		"arabic-indic":       "١٢٣",
		"nul byte":           "50\x0000",
		"letters":            "five",
		"newline":            "5000\n",
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAmount(s)
			if err == nil {
				t.Fatalf("%q was accepted as an amount", s)
			}
			if !errors.Is(err, ErrAmountGrammar) {
				t.Errorf("wrong diagnosis: want ErrAmountGrammar, got: %v", err)
			}
		})
	}
}

// An authorization to move a non-positive amount is not a narrower
// authorization. Signed forms are refused by the grammar (a sign is not part of
// an amount at all); zero is refused on value.
func TestParseAmount_RejectsNonPositive(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		_, err := ParseAmount("0")
		if !errors.Is(err, ErrAmountNotPositive) {
			t.Fatalf("want ErrAmountNotPositive, got: %v", err)
		}
	})
	t.Run("zero with decimals", func(t *testing.T) {
		_, err := ParseAmount("0.000")
		if !errors.Is(err, ErrAmountNotPositive) {
			t.Fatalf("want ErrAmountNotPositive, got: %v", err)
		}
	})
	for _, s := range []string{"-5000", "-0", "-0.0", "-1"} {
		t.Run("signed "+s, func(t *testing.T) {
			_, err := ParseAmount(s)
			if err == nil {
				t.Fatalf("%q was accepted", s)
			}
			if !errors.Is(err, ErrAmountGrammar) {
				t.Errorf("a sign should fail the grammar, got: %v", err)
			}
		})
	}
}

func TestParseAmount_RejectsEmpty(t *testing.T) {
	if _, err := ParseAmount(""); !errors.Is(err, ErrAmountEmpty) {
		t.Fatalf("want ErrAmountEmpty, got: %v", err)
	}
}

// Property: an accepted amount is always strictly positive, and is always a
// string big.Rat reads back to the same exact value. Nothing that is accepted
// may be ambiguous or non-positive, whatever the input.
func TestProperty_AcceptedAmountsArePositiveAndExact(t *testing.T) {
	accepted, rejected := 0, 0
	// Every 1-4 character string over a character set rich enough to cover the
	// grammar's boundaries and the shapes big.Rat would otherwise let through.
	alphabet := []byte("019.+-/xeE_, ")
	var walk func(prefix []byte, depth int)
	walk = func(prefix []byte, depth int) {
		if len(prefix) > 0 {
			s := string(prefix)
			r, err := ParseAmount(s)
			if err != nil {
				rejected++
			} else {
				accepted++
				if r.Sign() <= 0 {
					t.Fatalf("accepted a non-positive amount %q", s)
				}
				back, ok := new(big.Rat).SetString(s)
				if !ok || back.Cmp(r) != 0 {
					t.Fatalf("accepted %q but it does not read back exactly", s)
				}
			}
		}
		if depth == 0 {
			return
		}
		for _, c := range alphabet {
			walk(append(prefix, c), depth-1)
		}
	}
	walk(nil, 4)
	t.Logf("denominator: %d accepted and %d rejected amount strings exercised", accepted, rejected)
	if accepted == 0 || rejected == 0 {
		t.Fatal("the walk did not exercise both outcomes; the test proves nothing")
	}
}

// Property: the grammar is canonical — two DIFFERENT accepted strings never
// denote the same value, except through trailing zeros in the fraction, which
// are deliberately allowed because "5.00" is how money is written. This is what
// makes hashing the literal string safe.
func TestProperty_DistinctAcceptedStringsDenoteDistinctValues(t *testing.T) {
	seen := map[string]string{} // canonical value -> first string that produced it
	alphabet := []byte("019.")
	pairs := 0
	var walk func(prefix []byte, depth int)
	walk = func(prefix []byte, depth int) {
		if len(prefix) > 0 {
			s := string(prefix)
			if r, err := ParseAmount(s); err == nil {
				key := r.RatString()
				if prior, dup := seen[key]; dup {
					// Only a difference in trailing fractional zeros is permitted.
					if trimTrailingZeros(prior) != trimTrailingZeros(s) {
						t.Fatalf("two distinct amounts denote the same value: %q and %q", prior, s)
					}
				} else {
					seen[key] = s
				}
				pairs++
			}
		}
		if depth == 0 {
			return
		}
		for _, c := range alphabet {
			walk(append(prefix, c), depth-1)
		}
	}
	walk(nil, 5)
	t.Logf("denominator: %d accepted amount strings checked for aliasing", pairs)
}

func trimTrailingZeros(s string) string {
	if !containsDot(s) {
		return s
	}
	for len(s) > 0 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	if len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

func containsDot(s string) bool {
	for i := range s {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

// A leading zero has its own diagnosis. Without this assertion the branch that
// produces it can be deleted and the input still rejected by the next rule —
// which is how a check becomes decoration nobody notices losing.
func TestParseAmount_LeadingZeroIsDiagnosedAsSuch(t *testing.T) {
	for _, s := range []string{"007", "00", "0123", "00.5"} {
		t.Run(s, func(t *testing.T) {
			_, err := ParseAmount(s)
			if err == nil {
				t.Fatalf("%q was accepted", s)
			}
			if !errors.Is(err, ErrAmountGrammar) {
				t.Fatalf("want ErrAmountGrammar, got: %v", err)
			}
			if !containsSub(err.Error(), "leading zero") {
				t.Errorf("wrong diagnosis for %q: want the leading-zero reason, got: %v", s, err)
			}
		})
	}
}

// The invariant behind "one grammar": the adapters' gate and the parser agree on
// every input, always. If validAmount ever grows its own opinion, this fails.
func TestValidAmount_MatchesParseAmountExactly(t *testing.T) {
	inputs := []string{
		"", "0", "1", "5000", "0.5", "5.00", "18446744073709551616",
		"-1", "-0", "007", "0x2710", "1/3", "1e6", "+1", "NaN", "Inf",
		" 1", "1 ", "1,0", "1_0", ".5", "5.", "..", "５", "1.2.3", "abc",
	}
	agreed := 0
	for _, s := range inputs {
		_, perr := ParseAmount(s)
		verr := validAmount(s)
		if (perr == nil) != (verr == nil) {
			t.Fatalf("the adapters' gate and the parser disagree about %q: ParseAmount=%v validAmount=%v", s, perr, verr)
		}
		agreed++
	}
	t.Logf("denominator: %d inputs on which the adapter gate and the parser agree", agreed)
}

// And the wiring is real: an adapter's Validate refuses the same amounts. The
// chain-neutral adapter is used because it needs no chain-specific fixture, so
// the only thing varying here is the amount.
func TestGenericAdapter_RefusesTheSameAmounts(t *testing.T) {
	l, err := Get("none")
	if err != nil {
		t.Fatal(err)
	}
	base := TxnContext{Originator: "alice", Beneficiary: "bob", Currency: "USD", Timestamp: 1750000000}
	t.Run("accepts a canonical amount", func(t *testing.T) {
		tc := base
		tc.Amount = "100"
		if err := l.Validate(tc); err != nil {
			t.Fatalf("a canonical amount was refused by the adapter: %v", err)
		}
	})
	for _, s := range []string{"", "0", "-1", "007", "0x2710", "1/3", "1e6", "+1", " 1", "NaN"} {
		t.Run("refuses "+s, func(t *testing.T) {
			tc := base
			tc.Amount = s
			if err := l.Validate(tc); err == nil {
				t.Fatalf("the adapter accepted amount %q", s)
			}
		})
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
