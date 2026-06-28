// Package negotiate solves the Travel Rule "sunrise problem": two CASPs that
// must exchange Travel Rule information may not support the same payload privacy
// level. This package picks the strongest mode both sides support that is still
// at or above the local node's security floor — so a node degrades gracefully
// (ZK → sealed TRISA → cleartext TRP) without ever dropping below its policy.
//
// It is pure logic: no network, no crypto. A node advertises its Capabilities,
// learns the counterparty's, and calls Negotiate with its floor.
package negotiate

import (
	"errors"
	"fmt"
)

// Mode is a Travel Rule payload privacy level, strongest to weakest.
type Mode string

const (
	// ModeZK — SPT-Txn payload-level zero-knowledge attestation: the counterparty
	// receives proofs, not the PII or amount. Strongest.
	ModeZK Mode = "zk"
	// ModeSealedTRISA — TRISA Secure Envelope: PII encrypted in transit and at
	// rest, sealed to the recipient's key (counterparty still decrypts it).
	ModeSealedTRISA Mode = "sealed-trisa"
	// ModeCleartextTRP — plain TRP over mTLS: full IVMS101 delivered in the
	// (transport-encrypted) clear. Weakest; many nodes refuse it.
	ModeCleartextTRP Mode = "cleartext-trp"
)

// rank orders modes by security strength (higher is stronger).
var rank = map[Mode]int{
	ModeCleartextTRP: 1,
	ModeSealedTRISA:  2,
	ModeZK:           3,
}

var (
	// ErrNoCommonMode means the two parties share no payload mode at all.
	ErrNoCommonMode = errors.New("negotiate: no common Travel Rule mode")
	// ErrBelowFloor means the strongest shared mode is weaker than this node
	// requires — the node refuses rather than transmit below its floor.
	ErrBelowFloor = errors.New("negotiate: strongest shared mode is below the security floor")
	// ErrUnknownMode means an advertised mode is not recognised.
	ErrUnknownMode = errors.New("negotiate: unknown mode")
)

// Capabilities is the set of payload modes a party supports.
type Capabilities struct {
	Modes []Mode
}

// Supports reports whether m is advertised.
func (c Capabilities) Supports(m Mode) bool {
	for _, x := range c.Modes {
		if x == m {
			return true
		}
	}
	return false
}

// Negotiate returns the strongest Mode supported by both local and remote that
// is at least as strong as floor. It fails closed: an empty intersection yields
// ErrNoCommonMode, and an intersection whose best is weaker than floor yields
// ErrBelowFloor — the node never silently downgrades below its policy.
func Negotiate(local, remote Capabilities, floor Mode) (Mode, error) {
	floorRank, ok := rank[floor]
	if !ok {
		return "", fmt.Errorf("%w: floor %q", ErrUnknownMode, floor)
	}
	best := Mode("")
	bestRank := 0
	common := false
	for _, m := range local.Modes {
		r, ok := rank[m]
		if !ok {
			return "", fmt.Errorf("%w: %q", ErrUnknownMode, m)
		}
		if !remote.Supports(m) {
			continue
		}
		common = true
		if r > bestRank {
			best, bestRank = m, r
		}
	}
	if !common {
		return "", ErrNoCommonMode
	}
	if bestRank < floorRank {
		return "", fmt.Errorf("%w: best=%q floor=%q", ErrBelowFloor, best, floor)
	}
	return best, nil
}

// Stronger reports whether a is strictly stronger than b.
func Stronger(a, b Mode) bool { return rank[a] > rank[b] }
