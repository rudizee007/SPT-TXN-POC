package ledger

import "fmt"

// Avalanche is the Avalanche C-Chain (EVM) adapter. The C-Chain is
// EVM-equivalent, so the transfer shape is identical to Ethereum and reuses the
// same validation; this adapter exists so transaction-binding is labeled
// "avalanche" (a distinct chain tag, so hashes can't collide with the Ethereum
// adapter) rather than folded into "ethereum". Selection is by
// TxnContext.Chain == "avalanche". The same Solidity attestation-anchor and
// on-chain ZK verifier deploy on Avalanche (Fuji testnet / C-Chain mainnet)
// unchanged. Complements Avalanche's Encrypted ERC (eERC) confidential-transfer
// standard with the cross-VASP Travel Rule (grant work).
type Avalanche struct{}

func (Avalanche) Name() string { return "avalanche" }

func (Avalanche) Validate(tc TxnContext) error {
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
		return fmt.Errorf("currency required (AVAX or an ERC-20 / eERC token contract address)")
	}
	if tc.Currency != "AVAX" && !looksLikeEVMAddress(tc.Currency) {
		return fmt.Errorf("currency %q must be AVAX or a token contract address (0x…)", tc.Currency)
	}
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (Avalanche) Canonicalize(tc TxnContext) ([]byte, error) {
	// "avalanche" chain tag keeps the preimage distinct from the Ethereum adapter
	// even though both accept identical 0x-hex EVM addresses.
	return canonicalEncode([][2]string{
		{"chain", "avalanche"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"token", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(Avalanche{}) }
