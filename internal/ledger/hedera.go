package ledger

import (
	"fmt"
	"strings"
)

// Hedera is the Hedera Hashgraph adapter. It binds an SPT-Txn Token to a
// specific Hedera transfer (HBAR or an HTS token) without the core token
// packages ever importing it — selection is by TxnContext.Chain == "hedera".
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of a Hedera CryptoTransfer / TokenTransfer:
//     sender (originator), receiver (beneficiary), amount, currency (HBAR or an
//     HTS token id), and an optional transaction memo (Extra["memo"]).
//   - Accounts may be Hedera account IDs (shard.realm.num, e.g. 0.0.12345) or
//     EVM-address aliases (0x + 40 hex). Currency is "HBAR" or an HTS token id.
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission, and anchoring the attestation hash /
// audit root to the Hedera Consensus Service (HCS), belong to a separate client
// outside the authorization core (grant milestone A1).
type Hedera struct{}

func (Hedera) Name() string { return "hedera" }

func (Hedera) Validate(tc TxnContext) error {
	if !looksLikeHederaAccount(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not a Hedera account id (shard.realm.num) or 0x EVM alias", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeHederaAccount(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid Hedera account id or 0x EVM alias", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (HBAR, or an HTS token id like 0.0.<num>)")
	}
	// A Hedera transaction memo is capped at 100 bytes; enforce when present.
	if memo, ok := tc.Extra["memo"]; ok && len(memo) > 100 {
		return fmt.Errorf("memo exceeds the 100-byte Hedera limit (%d bytes)", len(memo))
	}
	return nil
}

func (Hedera) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order mirrors the transfer fields the authorization binds.
	// Explicit (not reflection) keeps the binding auditable, and identical bytes
	// on any host make spt_txn_context_hash verifiable cross-domain (step 8).
	return canonicalEncode([][2]string{
		{"chain", "hedera"},
		{"TransactionType", "CryptoTransfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"currency", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Hedera{}) }

// ── helpers (shape checks only; no checksum/network validation in POC) ───────

// looksLikeHederaAccount accepts a Hedera account id "shard.realm.num" (all
// non-negative integers, e.g. 0.0.12345) or an EVM-address alias (0x + 40 hex).
func looksLikeHederaAccount(s string) bool {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return isHex40(s[2:])
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if !isUintStr(p) {
			return false
		}
	}
	return true
}

func isUintStr(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
