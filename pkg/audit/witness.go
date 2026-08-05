package audit

// witness.go — external witness co-signing of transparency-log tree heads
// (docs/spec/RECEIPT-FORMAT.md §2.1; docs/THREAT-MODEL.md §3.6 adversary A5).
//
// A signed tree head proves the operator committed to a log state. It does not,
// by itself, stop a MALICIOUS operator from producing a DIFFERENT signed tree
// head over a rewritten history — the operator holds the log key. Witness
// co-signing closes that: an independent witness co-signs a tree head only after
// confirming it is an APPEND-ONLY extension of the last state that witness
// attested. A verifier then requires a threshold of witness co-signatures. A
// compromised operator therefore cannot produce a consistent alternate history
// that the witness set will co-sign — which is what makes the evidence
// trustworthy to a regulator, not merely to the customer.
//
// Standard library only (crypto/ed25519). The witness signature is
// domain-separated from operator signatures and bound to the operator identity
// so a co-signature cannot be replayed against a different operator's log.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
)

const witnessTag = "spt-txn-witness-cosign-v1"

var (
	// ErrRootMismatch means the presented log does not reproduce the signed root.
	ErrRootMismatch = errors.New("audit: presented log does not reproduce the signed root")
	// ErrNotAppendOnly means the new root is not an append-only extension of the
	// last root this witness attested — i.e. history was rewritten or truncated.
	ErrNotAppendOnly = errors.New("audit: signed root is not an append-only extension (history rewritten or regressed)")
	// ErrOperatorSig means the operator's signature on the tree head is invalid.
	ErrOperatorSig = errors.New("audit: operator signature on tree head invalid")
	// ErrThreshold means fewer than the required number of known witnesses co-signed.
	ErrThreshold = errors.New("audit: witness co-signature threshold not met")
)

// WitnessSig is one witness's co-signature over a SignedRoot.
type WitnessSig struct {
	WitnessID string `json:"witness_id"`
	Sig       []byte `json:"sig"`
}

// witnessPreimage binds a co-signature to the operator identity and the exact
// tree head, under a distinct domain tag.
func witnessPreimage(operatorPub ed25519.PublicKey, sr SignedRoot) []byte {
	sb := sr.signingBytes()
	b := make([]byte, 0, len(witnessTag)+1+len(operatorPub)+1+len(sb))
	b = append(b, witnessTag...)
	b = append(b, 0x00)
	b = append(b, operatorPub...)
	b = append(b, 0x00)
	b = append(b, sb...)
	return b
}

// Witness co-signs an operator's tree heads, enforcing append-only consistency
// across the heads it has seen. A Witness is stateful: it remembers the last
// (count, root) it attested and refuses to co-sign anything that is not a
// forward, append-only extension of it. Not safe for concurrent Cosign calls;
// serialize them (a witness attests a monotonic sequence).
type Witness struct {
	id        string
	key       ed25519.PrivateKey
	lastCount int
	lastRoot  []byte
}

// NewWitness constructs a witness with the given id and signing key.
func NewWitness(id string, key ed25519.PrivateKey) (*Witness, error) {
	if id == "" {
		return nil, errors.New("audit: witness id required")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("audit: bad witness key size")
	}
	return &Witness{id: id, key: key}, nil
}

// ID returns the witness identifier.
func (w *Witness) ID() string { return w.id }

// Public returns the witness's public key (for the verifier's witness set).
func (w *Witness) Public() ed25519.PublicKey { return w.key.Public().(ed25519.PublicKey) }

// Cosign verifies the operator's tree head against the presented log and, if
// this witness has a prior attestation, that the new state only appended to it;
// then returns a co-signature and advances the witness's anchor.
//
// entries is the operator's current full log (the witness recomputes roots from
// it — the POC stands in for a compact RFC 6962 consistency proof, which is the
// production optimization). The security property is identical: the witness
// only co-signs a state whose prefix at its last attested count reproduces the
// root it already attested.
func (w *Witness) Cosign(sr SignedRoot, operatorPub ed25519.PublicKey, entries []Entry) (WitnessSig, error) {
	// 1. Operator actually signed this tree head.
	if !VerifyRoot(sr, operatorPub) {
		return WitnessSig{}, ErrOperatorSig
	}
	// 2. The presented log reproduces the signed root exactly.
	if len(entries) != sr.Count || !bytes.Equal(MerkleRoot(entries), sr.Root) {
		return WitnessSig{}, ErrRootMismatch
	}
	// 3. Append-only: the new state must not regress, and its prefix at the last
	//    attested count must reproduce the previously attested root.
	if w.lastRoot != nil {
		if sr.Count < w.lastCount {
			return WitnessSig{}, fmt.Errorf("%w: count %d < last %d", ErrNotAppendOnly, sr.Count, w.lastCount)
		}
		if !bytes.Equal(MerkleRoot(entries[:w.lastCount]), w.lastRoot) {
			return WitnessSig{}, ErrNotAppendOnly
		}
	}
	// 4. Co-sign and advance the anchor.
	sig := ed25519.Sign(w.key, witnessPreimage(operatorPub, sr))
	w.lastCount = sr.Count
	w.lastRoot = append([]byte(nil), sr.Root...)
	return WitnessSig{WitnessID: w.id, Sig: sig}, nil
}

// CosignedRoot is a signed tree head plus the operator identity and the witness
// co-signatures gathered for it.
type CosignedRoot struct {
	SignedRoot
	OperatorPub []byte       `json:"operator_pub"`
	Cosigs      []WitnessSig `json:"cosigs"`
}

// VerifyCosigned checks the operator signature and that at least `threshold`
// DISTINCT known witnesses validly co-signed this exact tree head. witnessSet
// maps witness id to public key; a co-signature from an unknown id, an invalid
// signature, or a duplicate id does not count toward the threshold.
func VerifyCosigned(cr CosignedRoot, operatorPub ed25519.PublicKey, witnessSet map[string]ed25519.PublicKey, threshold int) error {
	if !bytes.Equal(cr.OperatorPub, operatorPub) {
		return fmt.Errorf("%w: operator identity mismatch", ErrOperatorSig)
	}
	if !VerifyRoot(cr.SignedRoot, operatorPub) {
		return ErrOperatorSig
	}
	pre := witnessPreimage(operatorPub, cr.SignedRoot)
	counted := make(map[string]bool)
	for _, cs := range cr.Cosigs {
		if counted[cs.WitnessID] {
			continue // one witness, one vote
		}
		pub, ok := witnessSet[cs.WitnessID]
		if !ok || len(pub) != ed25519.PublicKeySize {
			continue // unknown witness
		}
		if len(cs.Sig) == ed25519.SignatureSize && ed25519.Verify(pub, pre, cs.Sig) {
			counted[cs.WitnessID] = true
		}
	}
	if len(counted) < threshold {
		return fmt.Errorf("%w: %d of %d required", ErrThreshold, len(counted), threshold)
	}
	return nil
}
