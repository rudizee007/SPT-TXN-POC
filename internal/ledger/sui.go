package ledger

import (
	"fmt"
	"strings"
)

// Sui is the Sui (Move L1) adapter. It binds an SPT-Txn Token to a specific Sui
// transfer without the core token packages ever importing it — selection is by
// TxnContext.Chain == "sui".
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of a Sui transfer: sender (originator), receiver
//     (beneficiary), amount, and asset. Sui account addresses are 32-byte values
//     written as 0x + up to 64 hex chars. The asset is "SUI" or a Move coin type
//     tag ("0x2::sui::SUI", or any "<addr>::<module>::<struct>").
//   - Sui is object-centric and Move-based (like Aptos), so the SPT-Txn
//     attestation root anchors via a Move module/event rather than a memo field;
//     Sui's zkLogin / SuiNS identity primitives are the natural binding for the
//     humanAnchor (grant work).
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission, on-chain anchoring (a Sui Move
// module), and the zkLogin/SuiNS identity binding are grant work.
type Sui struct{}

func (Sui) Name() string { return "sui" }

func (Sui) Validate(tc TxnContext) error {
	if !looksLikeSuiAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not a Sui address (0x + up to 64 hex)", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeSuiAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid Sui address", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (SUI or a Move coin type tag 0x…::module::struct)")
	}
	if tc.Currency != "SUI" && !looksLikeSuiCoinType(tc.Currency) {
		return fmt.Errorf("currency %q must be SUI or a Move coin type tag (0x…::module::struct)", tc.Currency)
	}
	// Optional on-chain anchor: a 32-byte attestation root (64 hex), recorded by a
	// Sui Move anchor module (Sui has no native memo field).
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (Sui) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order; explicit (not reflection) keeps the binding auditable, and
	// identical bytes on any host make spt_txn_context_hash verifiable cross-domain
	// (step 8). The "sui" chain tag in the preimage prevents cross-chain collision.
	return canonicalEncode([][2]string{
		{"chain", "sui"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"asset", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Sui{}) }

// ── helpers (shape checks only; no on-chain existence / checksum validation) ──

// looksLikeSuiAddress accepts a 0x-prefixed account/object address: "0x" + 1..64
// hex chars (a 32-byte value). Shape only. Reuses isHexStr from starknet.go.
func looksLikeSuiAddress(s string) bool {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return false
	}
	h := s[2:]
	if len(h) < 1 || len(h) > 64 {
		return false
	}
	return isHexStr(h)
}

// looksLikeSuiCoinType accepts a Move coin type tag "<addr>::<module>::<struct>"
// (e.g. "0x2::sui::SUI"). Shape only; reuses isMoveIdent from aptos.go.
func looksLikeSuiCoinType(s string) bool {
	parts := strings.Split(s, "::")
	if len(parts) != 3 {
		return false
	}
	if !looksLikeSuiAddress(parts[0]) {
		return false
	}
	return isMoveIdent(parts[1]) && isMoveIdent(parts[2])
}
