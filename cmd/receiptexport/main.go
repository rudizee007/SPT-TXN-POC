// Command receiptexport reads an SPT-Txn transparency log (the JSONL audit
// log) and emits control-framework evidence rows — the auditor-consumable
// export over the enforcement record (docs/spec/RECEIPT-FORMAT.md §3).
//
// It maps each Transaction Receipt to the NIST SP 800-53 / DORA / SOC2
// controls its enforcement provides evidence for, and writes CSV or JSON that
// a GRC tool can import. We export to what customers already run; we do not
// build a dashboard.
//
// The receipts here come from the audit log's per-entry Detail (written by
// receiptlog.LogEmitter), which carries hashes and enums only — never payloads or
// PII. This tool therefore reconstructs the evidence view without ever needing
// the raw tokens.
//
// Usage:
//
//	receiptexport -log audit.jsonl [-framework NIST-SP-800-53|EU-DORA|SOC2] [-format csv|json]
package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/rudizee007/spt-txn-poc/internal/controlmap"
	"github.com/rudizee007/spt-txn-poc/internal/receiptlog"
	"github.com/rudizee007/spt-txn-poc/pkg/audit"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

func main() {
	logPath := flag.String("log", "", "path to the transparency log JSONL (required)")
	framework := flag.String("framework", "", "filter to one framework (NIST-SP-800-53|EU-DORA|SOC2); empty = all")
	format := flag.String("format", "csv", "output format: csv or json")
	flag.Parse()

	if *logPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	log, err := audit.Open(*logPath)
	if err != nil {
		fatal("open log: %v", err)
	}
	defer log.Close()
	if err := log.Verify(); err != nil {
		fatal("log integrity check failed (refusing to export from a tampered log): %v", err)
	}

	var allRows []controlmap.EvidenceRow
	for _, e := range log.Entries() {
		if e.Type != receiptlog.EventType {
			continue
		}
		r, ok := receiptFromDetail(e.Detail, e.Time)
		if !ok {
			continue
		}
		// The authoritative receipt hash is the audit entry's subject (set by
		// receiptlog.LogEmitter at emission), falling back to the detail field.
		rh := e.Subject
		if rh == "" {
			rh = e.Detail["receipt_hash"]
		}
		allRows = append(allRows, controlmap.Rows(r, rh, controlmap.Framework(*framework))...)
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(allRows); err != nil {
			fatal("encode json: %v", err)
		}
	case "csv":
		w := csv.NewWriter(os.Stdout)
		_ = w.Write([]string{"framework", "control_id", "control_title", "decision", "class", "rule_path", "receipt_hash", "pep", "policy_hash", "jurisdiction", "ts"})
		for _, r := range allRows {
			_ = w.Write([]string{r.Framework, r.ControlID, r.ControlTitle, r.Decision, r.Class, r.RulePath, r.ReceiptHash, r.PEP, r.PolicyHash, r.Jurisdiction, strconv.FormatInt(r.Timestamp, 10)})
		}
		w.Flush()
		if err := w.Error(); err != nil {
			fatal("write csv: %v", err)
		}
	default:
		fatal("unknown format %q (want csv or json)", *format)
	}

	fmt.Fprintf(os.Stderr, "exported %d evidence rows\n", len(allRows))
}

// receiptFromDetail reconstructs the receipt fields the exporter needs from an
// audit-log Detail map (written by receipt.AuditDetail). The receipt_hash is
// taken as authoritative from the detail (it was computed at emission over the
// signed receipt); we re-wrap it so controlmap.Rows can key evidence to it.
func receiptFromDetail(d map[string]string, ts int64) (receipt.Receipt, bool) {
	if d["receipt_v"] != receipt.Version {
		return receipt.Receipt{}, false
	}
	return receipt.Receipt{
		V:            d["receipt_v"],
		PEP:          d["pep"],
		Decision:     d["decision"],
		Class:        d["class"],
		RulePath:     d["rule_path"],
		TokenHash:    d["token_hash"],
		PolicyHash:   d["policy_hash"],
		IntentDigest: d["intent_digest"],
		Jurisdiction: d["jurisdiction"],
		TS:           ts,
		// Nonce/Sig are not needed for the evidence view; the receipt_hash in
		// the detail is the authoritative proof anchor and is re-emitted by
		// controlmap via the reconstructed receipt's Hash() only when present.
	}, true
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "receiptexport: "+format+"\n", args...)
	os.Exit(1)
}
