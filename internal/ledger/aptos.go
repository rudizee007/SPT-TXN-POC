package ledger

import (
	"fmt"
	"strings"
)

// Aptos is the Aptos (Move L1) adapter. It binds an SPT-Txn Token to a specific
// Aptos transfer without the core token packages ever importing it — selection
// is by TxnContext.Chain == "aptos".
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of an Aptos transfer: sender (originator),
//     receiver (beneficiary), amount, and asset. Aptos account addresses are
//     32-byte values written as 0x + up to 64 hex chars (leading zeros are
//     commonly omitted, e.g. 0x1). The asset is "APT", a Move coin type tag
//     ("0x1::aptos_coin::AptosCoin"), or a Fungible Asset metadata object
//     address (0x…). The Confidential Asset standard wraps any FA.
//   - Aptos has no transaction memo field; the SPT-Txn attestation root anchors
//     via a Move module/event (mirrors the Starknet Cairo anchor) rather than a
//     tx field. With Move account abstraction, an agent's account can enforce its
//     CT scope on-chain via a custom Move auth function — the agentic deliverable.
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission, on-chain anchoring (Move module), the
// Confidential-Asset-complementary Travel Rule flow, and the account-abstraction
// capability flow are grant work.
type Aptos struct{}

func (Aptos) Name() string { return "aptos" }

func (Aptos) Validate(tc TxnContext) error {
	if !looksLikeAptosAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not an Aptos address (0x + up to 64 hex)", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeAptosAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid Aptos address", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (APT, a Move coin type tag, or a Fungible Asset object address)")
	}
	if tc.Currency != "APT" && !looksLikeAptosCoinType(tc.Currency) && !looksLikeAptosAddress(tc.Currency) {
		return fmt.Errorf("currency %q must be APT, a Move coin type tag (0x…::module::struct), or an FA object address (0x…)", tc.Currency)
	}
	// Optional on-chain anchor: a 32-byte attestation root (64 hex), recorded by
	// a Move anchor module (Aptos has no native memo).
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (Aptos) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order mirrors the transfer the authorization binds. Explicit
	// (not reflection) keeps the binding auditable, and identical bytes on any
	// host make spt_txn_context_hash verifiable cross-domain (step 8). The "aptos"
	// chain tag in the preimage prevents cross-chain hash collision.
	return canonicalEncode([][2]string{
		{"chain", "aptos"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"asset", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Aptos{}) }

// ── helpers (shape checks only; no on-chain existence / checksum validation) ──

// looksLikeAptosAddress accepts a 0x-prefixed account/object address: "0x" +
// 1..64 hex chars (a 32-byte value; leading zeros are commonly omitted). Shape
// only. Reuses isHexStr from starknet.go.
func looksLikeAptosAddress(s string) bool {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return false
	}
	h := s[2:]
	if len(h) < 1 || len(h) > 64 {
		return false
	}
	return isHexStr(h)
}

// looksLikeAptosCoinType accepts a Move coin type tag of the form
// "<addr>::<module>::<struct>" (e.g. "0x1::aptos_coin::AptosCoin"): an Aptos
// address followed by two Move identifiers. Shape only.
func looksLikeAptosCoinType(s string) bool {
	parts := strings.Split(s, "::")
	if len(parts) != 3 {
		return false
	}
	if !looksLikeAptosAddress(parts[0]) {
		return false
	}
	return isMoveIdent(parts[1]) && isMoveIdent(parts[2])
}

// isMoveIdent reports whether s is a Move identifier: a non-empty run of
// letters, digits, and underscores that does not start with a digit.
func isMoveIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		isLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isLetter {
			return false
		}
		if !isLetter && !isDigit {
			return false
		}
	}
	return true
}
