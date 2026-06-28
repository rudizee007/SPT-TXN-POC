package ledger

import "fmt"

// Base is the Base (OP Stack, EVM L2) adapter. EVM-equivalent, so the transfer
// shape is identical to Ethereum and reuses the same validation; this adapter
// exists so transaction-binding is labeled "base" (a distinct chain tag, so
// hashes can't collide with the Ethereum/Optimism adapters) rather than folded
// into "ethereum". Selection is by TxnContext.Chain == "base". The same Solidity
// attestation-anchor and on-chain ZK verifier deploy unchanged.
type Base struct{}

func (Base) Name() string { return "base" }

func (Base) Validate(tc TxnContext) error {
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

func (Base) Canonicalize(tc TxnContext) ([]byte, error) {
	// "base" chain tag keeps the preimage distinct from the Ethereum/Optimism
	// adapters even though all accept identical 0x-hex EVM addresses.
	return canonicalEncode([][2]string{
		{"chain", "base"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"token", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Base{}) }
