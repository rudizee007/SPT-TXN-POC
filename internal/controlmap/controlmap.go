// Package controlmap maps SPT-Txn Transaction Receipts to security-control
// framework evidence — the thin export layer over the transparency log
// (docs/spec/RECEIPT-FORMAT.md §3). It answers the GRC question nobody else
// can: "this specific control was enforced at the moment of this transaction,
// and here is the cryptographic proof."
//
// This is DATA, not a platform: it emits evidence rows keyed by control id for
// the frameworks a bank/federal buyer already runs. We do not build a GRC
// dashboard — customers import these into the tools they already have.
package controlmap

import (
	"sort"

	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// Framework identifies a control catalogue.
type Framework string

const (
	NIST80053 Framework = "NIST-SP-800-53"
	DORA      Framework = "EU-DORA"
	SOC2      Framework = "SOC2"
)

// Control is one framework control an enforcement decision provides evidence
// for.
type Control struct {
	Framework Framework
	ID        string // e.g. "AC-3", "AU-10", "Art.9(2)", "CC6.1"
	Title     string
}

// controlsForReceipt returns the controls a receipt provides evidence toward,
// based on what the decision actually did. The mapping is deliberately
// conservative: a receipt evidences a control only when the enforcement it
// records is that control's subject.
func controlsForReceipt(r receipt.Receipt) []Control {
	var out []Control

	// Access enforcement: every decision (permit or deny) is an access-control
	// enforcement event.
	out = append(out,
		Control{NIST80053, "AC-3", "Access Enforcement"},
		Control{DORA, "Art.9(2)", "ICT access management controls"},
		Control{SOC2, "CC6.1", "Logical access security controls"},
	)

	// Non-repudiation / auditability: the receipt is a signed, logged record.
	out = append(out,
		Control{NIST80053, "AU-10", "Non-repudiation"},
		Control{NIST80053, "AU-2", "Event Logging"},
		Control{SOC2, "CC7.2", "Security event monitoring"},
	)

	// Denials that are policy violations evidence deny-by-default enforcement.
	if r.Decision == receipt.DecisionDeny && r.Class == receipt.ClassViolation {
		out = append(out,
			Control{NIST80053, "AC-6", "Least Privilege"},
			Control{DORA, "Art.9(4)(c)", "Strong authentication & least-privilege access"},
		)
	}

	// Availability-class denials evidence fail-closed handling of degradation.
	if r.Decision == receipt.DecisionDeny && r.Class == receipt.ClassUnavailable {
		out = append(out,
			Control{NIST80053, "SC-24", "Fail in Known State"},
			Control{DORA, "Art.11", "ICT business continuity / response"},
		)
	}

	// A receipt carrying an intent digest evidences transaction-level
	// authorization binding (agentic control).
	if r.IntentDigest != "" {
		out = append(out, Control{NIST80053, "AC-4", "Information Flow Enforcement"})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// EvidenceRow is one exported (control, receipt) evidence pairing.
type EvidenceRow struct {
	Framework    string `json:"framework"`
	ControlID    string `json:"control_id"`
	ControlTitle string `json:"control_title"`
	Decision     string `json:"decision"`
	Class        string `json:"class"`
	RulePath     string `json:"rule_path"`
	ReceiptHash  string `json:"receipt_hash"`
	PEP          string `json:"pep"`
	PolicyHash   string `json:"policy_hash"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
	Timestamp    int64  `json:"ts"`
}

// Rows expands a receipt into one evidence row per control it evidences,
// optionally filtered to a single framework (empty = all frameworks).
// receiptHash is the authoritative hash of the signed receipt — the proof
// anchor. The caller supplies it (from the transparency log's entry, or from
// receipt.Hash() on a freshly signed receipt) so this function needs neither
// the signature nor to recompute it.
func Rows(r receipt.Receipt, receiptHash string, only Framework) []EvidenceRow {
	var rows []EvidenceRow
	for _, c := range controlsForReceipt(r) {
		if only != "" && c.Framework != only {
			continue
		}
		rows = append(rows, EvidenceRow{
			Framework:    string(c.Framework),
			ControlID:    c.ID,
			ControlTitle: c.Title,
			Decision:     r.Decision,
			Class:        r.Class,
			RulePath:     r.RulePath,
			ReceiptHash:  receiptHash,
			PEP:          r.PEP,
			PolicyHash:   r.PolicyHash,
			Jurisdiction: r.Jurisdiction,
			Timestamp:    r.TS,
		})
	}
	return rows
}

// Frameworks lists the supported frameworks.
func Frameworks() []Framework { return []Framework{NIST80053, DORA, SOC2} }
