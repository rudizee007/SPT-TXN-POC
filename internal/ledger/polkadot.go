package ledger

import (
	"fmt"
	"strings"
)

// Polkadot is the Polkadot / Substrate adapter. It binds an SPT-Txn Token to a
// specific Polkadot (or parachain) transfer without the core token packages ever
// importing it — selection is by TxnContext.Chain == "polkadot".
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of a balances transfer: sender (originator),
//     receiver (beneficiary), amount, and asset. Accounts are SS58-encoded
//     (base58, a 32-byte AccountId32 with a network prefix) or the raw
//     0x-prefixed AccountId32 (0x + 64 hex). The asset is "DOT" or a parachain
//     asset symbol / id.
//   - Substrate exposes a native arbitrary-bytes field via system.remark, so the
//     SPT-Txn attestation root can anchor on-chain in a remark (analogous to the
//     XRPL memo) — or via an ink!/pallet anchor. KILT (DID/VC on Kusama) and the
//     Polkadot identity pallet are the natural binding for the humanAnchor.
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission, on-chain anchoring (system.remark or a
// pallet/ink! module), and the KILT/identity binding are grant work.
type Polkadot struct{}

func (Polkadot) Name() string { return "polkadot" }

func (Polkadot) Validate(tc TxnContext) error {
	if !looksLikePolkadotAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not an SS58 address or 0x AccountId32", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikePolkadotAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid Polkadot address", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (DOT, or a parachain asset symbol / id)")
	}
	// Optional on-chain anchor: a 32-byte attestation root (64 hex) carried in a
	// system.remark (Substrate's native arbitrary-bytes field).
	if ah, ok := tc.Extra["remark"]; ok && ah != "" && !isHex64(ah) {
		return fmt.Errorf("remark anchor must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (Polkadot) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order; explicit (not reflection) keeps the binding auditable, and
	// identical bytes on any host make spt_txn_context_hash verifiable cross-domain
	// (step 8). The "polkadot" chain tag prevents cross-chain hash collision.
	return canonicalEncode([][2]string{
		{"chain", "polkadot"},
		{"TransactionType", "balances.transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"asset", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Polkadot{}) }

// ── helpers (shape checks only; no SS58 checksum / on-chain existence in POC) ──

// looksLikePolkadotAddress accepts either a raw 0x AccountId32 (0x + 64 hex) or an
// SS58 string: base58 over the length window of a 32-byte account with a 1-byte
// network prefix (1 prefix + 32 key + 2 checksum = 35 bytes ≈ 46–50 base58
// chars). Shape only — it does not verify the blake2b SS58 checksum. Reuses
// isBase58 (solana.go) and isHex64 (stellar.go).
func looksLikePolkadotAddress(s string) bool {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return isHex64(s[2:])
	}
	if len(s) < 46 || len(s) > 50 {
		return false
	}
	return isBase58(s)
}
