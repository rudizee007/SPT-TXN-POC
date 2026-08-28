package ledger

import (
	"errors"
	"fmt"
	"math/big"
)

// The ways an amount can be refused. Separate sentinels because they are
// separate diagnoses, and because a test that cannot tell them apart cannot
// tell whether the branch it thinks it is exercising is the branch that fired.
var (
	// ErrAmountEmpty: no amount was supplied.
	ErrAmountEmpty = errors.New("amount required")
	// ErrAmountGrammar: the amount is not a canonical decimal string.
	ErrAmountGrammar = errors.New("amount is not a canonical decimal string")
	// ErrAmountNotPositive: the amount parses but authorizes nothing.
	ErrAmountNotPositive = errors.New("amount must be positive")
)

// ParseAmount is THE amount parser for this system. Every place that decides
// whether an amount is acceptable — the ledger adapters' Validate, and the
// tbac projection of a transaction onto a capability's ceiling — goes through
// this function, so that no two of them can disagree about what a number is.
//
// # Grammar
//
// An amount is a canonical, unsigned decimal string:
//
//	amount     = int [ "." frac ]
//	int        = "0" / ( %x31-39 *DIGIT )      ; no leading zeros
//	frac       = 1*DIGIT                        ; at least one digit after the point
//	DIGIT      = %x30-39                        ; ASCII only
//
// and its value MUST be strictly greater than zero.
//
// # Why this is narrower than big.Rat
//
// The obvious implementation, new(big.Rat).SetString(s), accepts a great deal
// more than a decimal string: fractions ("1/3"), hexadecimal, binary and octal
// prefixes ("0x2710" is 10000), and exponents ("1e6"). That matters here because
// the amount is compared as a NUMBER against the capability's ceiling and then
// hashed as a LITERAL STRING into spt_txn_context_hash. An authorizer that reads
// "0x2710" as 10000 and an executor whose decimal parser reads it as an error —
// or as 0, or as 2710 — have authorized different transactions while agreeing on
// the hash. The narrow grammar removes that class: every accepted string is read
// as the same VALUE by every conforming decimal parser.
//
// It does not make the ENCODING unique, and it does not claim to. "5", "5.0" and
// "5.00" are three accepted spellings of five and therefore three preimages for
// one economic transaction — harmless here, because both sides hash the same
// literal, but a caller that needs one canonical spelling per value has to
// normalise separately. Trailing zeros are permitted deliberately: "5.00" is how
// a currency amount is written. Leading zeros are not, because "007" and "7"
// buy nothing and only add preimages.
//
// What the grammar does NOT bound is SCALE. Unbounded fractional digits are
// accepted, and no adapter narrows them per chain, so "1.0000001" is authorizable
// for a currency whose ledger has six decimals — the executor rounds and moves a
// different amount than was authorized while the context hash still matches. A
// per-chain decimals check at the adapter boundary is the missing half; until it
// exists this grammar bounds the FORM of an amount, not its representability on
// the chain it names.
//
// A sign is refused rather than parsed: an authorization to move a negative
// amount is not a narrower authorization, it is a different transaction (often
// the reverse one), and "-5000 <= 5000" is true, so a signed amount that reached
// a ceiling comparison would pass it.
//
// The returned *big.Rat is exact — no float64 appears anywhere on this path, so
// values beyond 2^53 (XRP drops, wei) compare correctly.
func ParseAmount(s string) (*big.Rat, error) {
	if s == "" {
		return nil, ErrAmountEmpty
	}
	if err := checkAmountGrammar(s); err != nil {
		return nil, err
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		// Unreachable for a string that passed the grammar; kept because "the
		// grammar guarantees it" is the sort of claim that stops being true
		// during a refactor, and failing closed costs nothing.
		return nil, fmt.Errorf("%w: %q", ErrAmountGrammar, s)
	}
	if r.Sign() <= 0 {
		return nil, fmt.Errorf("%w: %q", ErrAmountNotPositive, s)
	}
	return r, nil
}

func checkAmountGrammar(s string) error {
	bad := func(why string) error {
		return fmt.Errorf("%w (%s): %q", ErrAmountGrammar, why, s)
	}
	i := 0
	// Integer part: "0", or a non-zero digit followed by any digits.
	if i >= len(s) {
		return bad("empty")
	}
	switch {
	case s[i] == '0':
		i++
		// A leading zero may only be followed by the decimal point.
		if i < len(s) && s[i] != '.' {
			return bad("leading zero")
		}
	case s[i] >= '1' && s[i] <= '9':
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	default:
		return bad("must start with a digit")
	}
	if i == len(s) {
		return nil
	}
	// Fractional part.
	if s[i] != '.' {
		return bad("unexpected character after the integer part")
	}
	i++
	if i == len(s) {
		return bad("no digits after the decimal point")
	}
	for i < len(s) {
		if s[i] < '0' || s[i] > '9' {
			return bad("non-digit in the fractional part")
		}
		i++
	}
	return nil
}
