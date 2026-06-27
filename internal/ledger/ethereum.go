package ledger

import (
	"fmt"
	"strings"
)

// Ethereum is the Ethereum (and EVM-compatible L1/L2) adapter. It binds an
// SPT-Txn Token to a specific EVM transfer without the core token packages ever
// importing it — selection is by TxnContext.Chain == "ethereum".
//
// Because the major L2s (Arbitrum, Optimism, Base, Scroll, Linea, …) are
// EVM-equivalent, this one adapter — and the companion Solidity attestation
// anchor (see solidity/AttestationAnchor.sol) — covers Ethereum L1 and every
// EVM L2 with the same address/currency shape. "Build once, run everywhere."
//
// Scope of this adapter (POC):
//   - Canonicalizes the fields of an EVM transfer: sender (originator), receiver
//     (beneficiary), amount, and asset ("ETH" or an ERC-20 token contract
//     address). EVM account/contract addresses are 0x + exactly 40 hex chars
//     (20 bytes); checksum (EIP-55) is not enforced here (shape only).
//   - EVM has no transaction memo; the SPT-Txn attestation root anchors via the
//     Solidity anchor contract (an event / on-chain record), not a tx field.
//
// It does NOT submit transactions or touch the network; it only produces the
// deterministic hash preimage. Submission, on-chain anchoring (Solidity
// contract), and an on-chain ZK verifier are integration/grant work.
type Ethereum struct{}

func (Ethereum) Name() string { return "ethereum" }

func (Ethereum) Validate(tc TxnContext) error {
	if !looksLikeEVMAddress(tc.Beneficiary) {
		return fmt.Errorf("beneficiary %q is not an EVM address (0x + 40 hex, 20 bytes)", tc.Beneficiary)
	}
	if tc.Originator != "" && !looksLikeEVMAddress(tc.Originator) {
		return fmt.Errorf("originator %q is not a valid EVM address", tc.Originator)
	}
	if err := validAmount(tc.Amount); err != nil {
		return err
	}
	if tc.Currency == "" {
		return fmt.Errorf("currency required (ETH or an ERC-20 token contract address)")
	}
	if tc.Currency != "ETH" && !looksLikeEVMAddress(tc.Currency) {
		return fmt.Errorf("currency %q must be ETH or an ERC-20 token contract address (0x…)", tc.Currency)
	}
	// Optional on-chain anchor: a 32-byte attestation root (64 hex), recorded by
	// the Solidity anchor contract as a bytes32.
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (Ethereum) Canonicalize(tc TxnContext) ([]byte, error) {
	// Fixed field order mirrors the transfer the authorization binds. Explicit
	// (not reflection) keeps the binding auditable, and identical bytes on any
	// host make spt_txn_context_hash verifiable cross-domain (step 8). The
	// "ethereum" chain tag in the preimage prevents cross-chain hash collision
	// (e.g. with the Starknet adapter, which also uses 0x-hex addresses).
	return canonicalEncode([][2]string{
		{"chain", "ethereum"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"token", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Ethereum{}) }

// ── helpers (shape checks only; no EIP-55 checksum / on-chain existence) ──────

// looksLikeEVMAddress accepts a 0x-prefixed 20-byte address: "0x" + exactly 40
// hex chars. Shape only. Reuses isHexStr from starknet.go.
func looksLikeEVMAddress(s string) bool {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return false
	}
	h := s[2:]
	if len(h) != 40 {
		return false
	}
	return isHexStr(h)
}
