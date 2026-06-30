package ledger

import "fmt"

// XLayer is the OKX X Layer (EVM L2) adapter. X Layer is EVM-compatible (built
// with Polygon CDK, later an OP-Stack optimistic rollup) and its native gas
// asset is OKB, so the transfer shape is identical to Ethereum apart from the
// native currency label, and it reuses the same validation; this adapter exists
// so transaction-binding is labeled "xlayer" (a distinct chain tag, so hashes
// can't collide with the Ethereum or other EVM adapters). Selection is by
// TxnContext.Chain == "xlayer". The same Solidity attestation-anchor and
// on-chain ZK verifier deploy on X Layer unchanged.
type XLayer struct{}

func (XLayer) Name() string { return "xlayer" }

func (XLayer) Validate(tc TxnContext) error {
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
		return fmt.Errorf("currency required (OKB or an ERC-20 token contract address)")
	}
	if tc.Currency != "OKB" && !looksLikeEVMAddress(tc.Currency) {
		return fmt.Errorf("currency %q must be OKB or an ERC-20 token contract address (0x…)", tc.Currency)
	}
	if ah, ok := tc.Extra["anchor_hash"]; ok && !isHex64(ah) {
		return fmt.Errorf("anchor_hash must be 64 hex chars (32 bytes)")
	}
	return nil
}

func (XLayer) Canonicalize(tc TxnContext) ([]byte, error) {
	return canonicalEncode([][2]string{
		{"chain", "xlayer"},
		{"TransactionType", "Transfer"},
		{"sender", tc.Originator},
		{"receiver", tc.Beneficiary},
		{"amount", tc.Amount},
		{"token", tc.Currency},
		{"timestamp", fmt.Sprintf("%d", tc.Timestamp)},
	}, tc.Extra)
}

func init() { Register(XLayer{}) }
