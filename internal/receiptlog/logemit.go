package receiptlog

// Package receiptlog is glue between receipt emission and the transparency log
// (internal/audit). This is the reference Emitter used by the decision core:
// sign with the log key, append to the hash-chained log, and only then report
// success. An error anywhere means "not durably logged", and the decision
// core converts that into DENY (unavailable).

import (
	"crypto/ed25519"
	"errors"

	"github.com/rudizee007/spt-txn-poc/internal/audit"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

// EventType is the audit log event type for transaction receipts.
const EventType = "txn_receipt"

// LogEmitter signs receipts with the log key and appends them to the
// transparency log. Safe for concurrent use (audit.Log serializes appends).
type LogEmitter struct {
	log *audit.Log
	key ed25519.PrivateKey
}

// NewLogEmitter wires a signing key and an open audit log.
func NewLogEmitter(log *audit.Log, logKey ed25519.PrivateKey) (*LogEmitter, error) {
	if log == nil {
		return nil, errors.New("receiptlog: nil audit log")
	}
	if len(logKey) != ed25519.PrivateKeySize {
		return nil, errors.New("receiptlog: bad log key size")
	}
	return &LogEmitter{log: log, key: logKey}, nil
}

// Emit signs r, appends it to the log, and returns the receipt hash. The
// subject of the log entry is the receipt hash; the detail map carries only
// hashes and enums (audit's no-PII gate applies).
func (e *LogEmitter) Emit(r *receipt.Receipt) (string, error) {
	if err := r.Sign(e.key); err != nil {
		return "", err
	}
	hash, err := r.Hash()
	if err != nil {
		return "", err
	}
	detail, err := r.AuditDetail()
	if err != nil {
		return "", err
	}
	if _, err := e.log.Append(EventType, hash, detail); err != nil {
		return "", err
	}
	return hash, nil
}
