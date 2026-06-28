package ledger

import "fmt"

// Optimism is the Optimism (OP Stack, EVM L2) adapter. EVM-equivalent, so the
// transfer shape is identical to Ethereum and reuses the same validation; this
// adapter exists so transaction-binding is labeled "optimism" (a distinct chain
// tag, so hashes can't collide with the Ethereum/Base adapters) rather than
// folded into "ethereum". Selection is by TxnContext.Chain == "optimism". The
// same Solidity attestation-anchor and on-chain ZK verifier deploy unchanged.
type Optimism struct{}

func (Optimism) Name() string { return "optimism" }

func (Optimism) Validate(tc TxnContext) error {
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
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (Optimism) Canonicalize(tc TxnContext) ([]byte, error) {
	// "optimism" chain tag keeps the preimage distinct from the Ethereum/Base
	// adapters even though all accept identical 0x-hex EVM addresses.
	return canonicalEncode([][2]string{
		{"chain", "optimism"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"token", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Optimism{}) }
