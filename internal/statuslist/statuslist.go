// Package statuslist implements the IETF Token Status List
// (draft-ietf-oauth-status-list-21) for scalable, offline-checkable,
// fail-closed per-token revocation. Spec: docs/spec/STATUS-LIST.md.
//
// One small, signed, compressed bit array encodes the status of every token an
// issuer minted. A verifier holding a cached, signed snapshot checks a token's
// index against it with no call home; a missing, stale, or unsigned list fails
// CLOSED (docs/THREAT-MODEL.md §3.3, §4.6).
//
// Standard library only: compress/zlib (RFC 1950/1951), crypto/ed25519.
package statuslist

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// Status is a per-token status value.
type Status uint8

const (
	StatusValid     Status = 0 // not revoked or suspended
	StatusInvalid   Status = 1 // permanently revoked
	StatusSuspended Status = 2 // temporarily suspended
)

// maxDecompressed bounds a decompressed list to defeat a zip-bomb in a
// maliciously crafted Status List Token (parser-DoS guard). 16 MiB covers a
// 1-bit list of ~134M entries.
const maxDecompressed = 16 << 20

var (
	ErrBits       = errors.New("statuslist: bits must be 1, 2, 4, or 8")
	ErrIndex      = errors.New("statuslist: index out of range")
	ErrStatusSize = errors.New("statuslist: status value exceeds bits width")
	ErrDecode     = errors.New("statuslist: malformed encoded list")
	ErrTooLarge   = errors.New("statuslist: decompressed list exceeds bound")
)

// List is a mutable bit-packed status list.
type List struct {
	bits    int    // 1, 2, 4, or 8
	entries int    // number of referenced tokens
	data    []byte // packed big-endian within each byte, MSB-first

	// notAfter is the snapshot's own expiry, carried from the Status List
	// Token it was verified from. Zero means "undated", which Resolver.Check
	// treats as stale: a revocation snapshot with no known validity cannot be
	// shown to be current, and revocation data that cannot be shown current is
	// exactly what must not be trusted. Decode alone leaves this zero, so a
	// list built from raw encoded bytes is unusable for decisions until it has
	// been through VerifyToken — which is the intended direction.
	notAfter int64
}

// New creates a zero-initialised (all VALID) list of n entries at the given
// bit width.
func New(bits, n int) (*List, error) {
	if !validBits(bits) {
		return nil, ErrBits
	}
	if n < 0 {
		return nil, fmt.Errorf("statuslist: negative length")
	}
	return &List{bits: bits, entries: n, data: make([]byte, byteLen(bits, n))}, nil
}

func validBits(b int) bool { return b == 1 || b == 2 || b == 4 || b == 8 }

func byteLen(bits, n int) int {
	totalBits := bits * n
	return (totalBits + 7) / 8
}

// Len returns the number of entries.
func (l *List) Len() int { return l.entries }

// Bits returns the per-entry bit width.
func (l *List) Bits() int { return l.bits }

// Get returns the status at index i.
func (l *List) Get(i int) (Status, error) {
	if i < 0 || i >= l.entries {
		return 0, fmt.Errorf("%w: %d not in [0,%d)", ErrIndex, i, l.entries)
	}
	// Entries are packed MSB-first within each byte, per the draft's bit
	// concatenation: entry k occupies bit offset k*bits from the stream start.
	bitPos := i * l.bits
	var v uint16
	for b := 0; b < l.bits; b++ {
		p := bitPos + b
		byteIdx := p / 8
		bitInByte := 7 - (p % 8) // MSB-first
		bit := (l.data[byteIdx] >> uint(bitInByte)) & 1
		v = (v << 1) | uint16(bit)
	}
	return Status(v), nil
}

// Set assigns the status at index i. The value must fit in the bit width.
func (l *List) Set(i int, s Status) error {
	if i < 0 || i >= l.entries {
		return fmt.Errorf("%w: %d not in [0,%d)", ErrIndex, i, l.entries)
	}
	if int(s) >= (1 << l.bits) {
		return fmt.Errorf("%w: status %d needs more than %d bits", ErrStatusSize, s, l.bits)
	}
	bitPos := i * l.bits
	for b := 0; b < l.bits; b++ {
		p := bitPos + b
		byteIdx := p / 8
		bitInByte := 7 - (p % 8)
		// bit (MSB-first) of the value: the top bit first.
		bit := (uint8(s) >> uint(l.bits-1-b)) & 1
		mask := uint8(1) << uint(bitInByte)
		if bit == 1 {
			l.data[byteIdx] |= mask
		} else {
			l.data[byteIdx] &^= mask
		}
	}
	return nil
}

// Encoded is the wire form of a Status List (draft §status_list object).
type Encoded struct {
	Bits int    `json:"bits"`
	Lst  string `json:"lst"` // base64url(zlib(deflate(data))), no padding
}

// Encode compresses and encodes the list for transport.
func (l *List) Encode() (Encoded, error) {
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return Encoded{}, err
	}
	if _, err := zw.Write(l.data); err != nil {
		return Encoded{}, err
	}
	if err := zw.Close(); err != nil {
		return Encoded{}, err
	}
	return Encoded{
		Bits: l.bits,
		Lst:  base64.RawURLEncoding.EncodeToString(buf.Bytes()),
	}, nil
}

// Decode reconstructs a list from its wire form. `entries` is the number of
// referenced tokens the list covers (the byte length alone is ambiguous about
// trailing padding bits); pass the issuer-declared length. If entries <= 0 the
// list length is inferred as the maximum the decompressed bytes can hold.
func Decode(e Encoded, entries int) (*List, error) {
	if !validBits(e.Bits) {
		return nil, ErrBits
	}
	raw, err := base64.RawURLEncoding.DecodeString(e.Lst)
	if err != nil {
		return nil, fmt.Errorf("%w: base64: %v", ErrDecode, err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: zlib header: %v", ErrDecode, err)
	}
	defer zr.Close()
	data, err := io.ReadAll(io.LimitReader(zr, maxDecompressed+1))
	if err != nil {
		return nil, fmt.Errorf("%w: inflate: %v", ErrDecode, err)
	}
	if len(data) > maxDecompressed {
		return nil, ErrTooLarge
	}
	maxEntries := (len(data) * 8) / e.Bits
	if entries <= 0 {
		entries = maxEntries
	}
	if entries > maxEntries {
		return nil, fmt.Errorf("%w: declared %d entries exceeds %d the bytes hold", ErrDecode, entries, maxEntries)
	}
	return &List{bits: e.Bits, entries: entries, data: data}, nil
}
