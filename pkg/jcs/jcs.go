// Package jcs is the single shared RFC 8785 (JSON Canonicalization Scheme)
// implementation for the SPT-Txn trust boundary, restricted to the accepted
// subset defined in docs/spec/DELEGATION-INTENT-MCP.md §2.2.
//
// THIS IS THE ONLY CANONICALIZER. The issuer path (intent digest computation,
// receipt signing input) and the verifier path (recomputing the digest of the
// actual call) MUST both go through this package. A second implementation
// anywhere in the tree is a defect: two canonicalizers WILL diverge over time,
// and a divergence is a full authorization bypass (docs/THREAT-MODEL.md §4.1).
//
// Subset rules — reject, never normalize:
//
//   - Objects with unique member names only. A duplicate member name is
//     rejected at parse, not resolved by first- or last-wins.
//   - Numbers must be integers with |n| ≤ 2^53−1, no fraction, no exponent,
//     no negative zero. Anything else is rejected. Monetary amounts are
//     decimal strings by profile, never JSON numbers.
//   - Strings must be valid UTF-8 and must not contain U+FFFD (REPLACEMENT
//     CHARACTER). Go's JSON decoding maps invalid escapes and invalid bytes
//     to U+FFFD, which would let two distinct raw inputs canonicalize to the
//     same bytes; banning the character closes that ambiguity class.
//   - Nesting depth is bounded (MaxDepth) and the bound fails closed.
//
// Standard library only. No custom crypto — this package only produces
// deterministic bytes; hashing happens at the call sites with crypto/sha256.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth is the maximum object/array nesting depth accepted. Exceeding it
// is a rejection (fail closed), not a truncation.
const MaxDepth = 64

// MaxInt is the largest number magnitude accepted (2^53 − 1), per RFC 8785's
// reliance on IEEE 754 double interoperability.
const MaxInt = int64(1)<<53 - 1

var (
	// ErrDuplicateKey is returned when an object carries the same member name twice.
	ErrDuplicateKey = errors.New("jcs: duplicate object member")
	// ErrNumber is returned for any number outside the accepted integer subset.
	ErrNumber = errors.New("jcs: number outside accepted subset (integers |n| <= 2^53-1 only; use decimal strings for amounts)")
	// ErrDepth is returned when nesting exceeds MaxDepth.
	ErrDepth = errors.New("jcs: nesting depth exceeds bound")
	// ErrString is returned for strings that are not valid UTF-8 or contain U+FFFD.
	ErrString = errors.New("jcs: string not valid UTF-8 or contains U+FFFD")
	// ErrType is returned for Go values outside the accepted set.
	ErrType = errors.New("jcs: unsupported value type")
)

// Canonicalize serializes a decoded JSON value (map[string]any, []any,
// string, bool, nil, json.Number, or Go integer types) into RFC 8785
// canonical bytes under the subset rules. It is deterministic: equal values
// yield equal bytes.
func Canonicalize(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := appendValue(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalizeRaw strictly parses raw JSON bytes (rejecting duplicate keys,
// out-of-subset numbers, over-deep nesting, trailing data) and returns the
// canonical form. This is the entry point for anything received off the wire.
func CanonicalizeRaw(raw []byte) ([]byte, error) {
	v, err := ParseStrict(raw)
	if err != nil {
		return nil, err
	}
	return Canonicalize(v)
}

// ParseStrict decodes raw JSON under the subset rules and returns the value
// tree (map[string]any / []any / string / bool / nil / json.Number where the
// number has already passed the integer-subset check). Trailing non-space
// content after the first value is rejected.
func ParseStrict(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	// Reject trailing content: a second value, garbage, or another token.
	// Only a clean io.EOF is acceptable after the first value.
	if tok, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("jcs: trailing data after JSON value: %v", tok)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("jcs: trailing garbage after JSON value: %w", err)
	}
	return v, nil
}

// parseValue consumes exactly one JSON value from dec.
func parseValue(dec *json.Decoder, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, ErrDepth
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("jcs: parse: %w", err)
	}
	return parseFromToken(dec, tok, depth)
}

func parseFromToken(dec *json.Decoder, tok json.Token, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, ErrDepth
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := make(map[string]any)
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("jcs: parse key: %w", err)
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errors.New("jcs: object key is not a string")
				}
				if err := checkString(key); err != nil {
					return nil, err
				}
				if _, dup := obj[key]; dup {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, key)
				}
				val, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, fmt.Errorf("jcs: parse object end: %w", err)
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, fmt.Errorf("jcs: parse array end: %w", err)
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("jcs: unexpected delimiter %v", t)
		}
	case string:
		if err := checkString(t); err != nil {
			return nil, err
		}
		return t, nil
	case json.Number:
		if _, err := checkNumberLiteral(t.String()); err != nil {
			return nil, err
		}
		return t, nil
	case bool:
		return t, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrType, tok)
	}
}

// appendValue writes the canonical form of v to buf.
func appendValue(buf *bytes.Buffer, v any, depth int) error {
	if depth > MaxDepth {
		return ErrDepth
	}
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		if err := checkString(t); err != nil {
			return err
		}
		appendString(buf, t)
	case json.Number:
		n, err := checkNumberLiteral(t.String())
		if err != nil {
			return err
		}
		buf.WriteString(strconv.FormatInt(n, 10))
	case int:
		return appendInt(buf, int64(t))
	case int8:
		return appendInt(buf, int64(t))
	case int16:
		return appendInt(buf, int64(t))
	case int32:
		return appendInt(buf, int64(t))
	case int64:
		return appendInt(buf, t)
	case uint:
		return appendUint(buf, uint64(t))
	case uint8:
		return appendUint(buf, uint64(t))
	case uint16:
		return appendUint(buf, uint64(t))
	case uint32:
		return appendUint(buf, uint64(t))
	case uint64:
		return appendUint(buf, t)
	case float64:
		// Accepted only when integral, in range, and not negative zero.
		if math.IsNaN(t) || math.IsInf(t, 0) || t != math.Trunc(t) {
			return ErrNumber
		}
		if t == 0 && math.Signbit(t) {
			return ErrNumber
		}
		if t > float64(MaxInt) || t < -float64(MaxInt) {
			return ErrNumber
		}
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			if err := checkString(k); err != nil {
				return err
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			appendString(buf, k)
			buf.WriteByte(':')
			if err := appendValue(buf, t[k], depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendValue(buf, e, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		return fmt.Errorf("%w: %T", ErrType, v)
	}
	return nil
}

func appendInt(buf *bytes.Buffer, n int64) error {
	if n > MaxInt || n < -MaxInt {
		return ErrNumber
	}
	buf.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func appendUint(buf *bytes.Buffer, n uint64) error {
	if n > uint64(MaxInt) {
		return ErrNumber
	}
	buf.WriteString(strconv.FormatUint(n, 10))
	return nil
}

// checkNumberLiteral accepts only /^-?(0|[1-9][0-9]*)$/ within ±(2^53−1),
// excluding "-0". No fractions, no exponents, no leading zeros.
func checkNumberLiteral(s string) (int64, error) {
	if s == "" || s == "-" || s == "-0" {
		return 0, ErrNumber
	}
	body := s
	if body[0] == '-' {
		body = body[1:]
	}
	if body == "" {
		return 0, ErrNumber
	}
	if body[0] == '0' && len(body) > 1 {
		return 0, ErrNumber // leading zero (also catches 0.5, 00)
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return 0, ErrNumber // '.', 'e', 'E', '+', anything non-digit
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, ErrNumber
	}
	if n > MaxInt || n < -MaxInt {
		return 0, ErrNumber
	}
	return n, nil
}

// checkString rejects invalid UTF-8 and any occurrence of U+FFFD.
func checkString(s string) error {
	if !utf8.ValidString(s) {
		return ErrString
	}
	if strings.ContainsRune(s, utf8.RuneError) {
		return ErrString
	}
	return nil
}

// appendString writes the RFC 8785 §3.2.2.2 serialization of s: the two-char
// escapes \" \\ \b \f \n \r \t, other C0 controls as lowercase \u00xx, and
// every other character as literal UTF-8.
func appendString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// utf16Less reports whether a sorts before b when both are viewed as
// sequences of UTF-16 code units, per RFC 8785 §3.2.3. This differs from
// byte-wise UTF-8 comparison for characters U+E000..U+FFFF vs supplementary
// characters (which encode as surrogate pairs starting 0xD800..0xDBFF).
func utf16Less(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
