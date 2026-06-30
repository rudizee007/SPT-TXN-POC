package ledger

import "fmt"

// BSC is the BNB Smart Chain (EVM L1) adapter. BSC is EVM-compatible, so the
// transfer shape is identical to Ethereum and reuses the same validation; this
// adapter exists so transaction-binding is labeled "bsc" (a distinct chain tag,
// so hashes can't collide with the Ethereum or other EVM adapters) rather than
// folded into "ethereum". Selection is by TxnContext.Chain == "bsc". The same
// Solidity attestation-anchor and on-chain ZK verifier deploy on BSC unchanged
// (the EVM "build once, deploy many" property). opBNB (OP Stack L2) is covered
// the same way via its own tag if needed.
type BSC struct{}

func (BSC) Name() string { return "bsc" }

func (BSC) Validate(tc TxnContext) error {
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
		return fmt.Errorf("currency required (BNB or a BEP-20 token contract address)")
	}
	if tc.Currency != "BNB" && !looksLikeEVMAddress(tc.Currency) {
		return fmt.Errorf("currency %q must be BNB or a BEP-20 token contract address (0x…)", tc.Currency)
	}
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (BSC) Canonicalize(tc TxnContext) ([]byte, error) {
	// "bsc" chain tag keeps the preimage distinct from the Ethereum adapter
	// even though both accept identical 0x-hex EVM addresses.
	return canonicalEncode([][2]string{
		{"chain", "bsc"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"token", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(BSC{}) }
