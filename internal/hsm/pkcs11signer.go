//go:build pkcs11

// Package hsm provides a PKCS#11-backed crypto.Signer for SPT-Txn issuer keys.
// Signing happens inside a token (SoftHSM2 today; AWS/GCP KMS or a hardware HSM
// later, unchanged), so the Ed25519 private key is generated in and never leaves
// the token — it is never loaded into process memory or written to disk.
//
// Build behind the `pkcs11` tag after adding the dependency:
//
//	go get github.com/miekg/pkcs11
//	CGO_ENABLED=1 go build -tags pkcs11 ./...
//
// (miekg/pkcs11 dlopens the module .so, so cgo must be enabled. On OpenBSD the
// SoftHSM2 module is /usr/local/lib/softhsm/libsofthsm2.so.)
//
// Because it satisfies crypto.Signer, wherever the issuer code currently takes an
// ed25519.PrivateKey it can take a crypto.Signer and pass either an on-disk key
// (ed25519.PrivateKey already implements crypto.Signer) or this HSM signer.
package hsm

import (
	"crypto"
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/miekg/pkcs11"
)

// ckmEDDSA is CKM_EDDSA from the PKCS#11 v3.0 spec (0x00001057). miekg/pkcs11
// v1.1.2 does not export it, so define it here. SoftHSM2 and cloud HSMs use this
// mechanism for pure Ed25519 signing.
const ckmEDDSA = 0x00001057

// Config selects the module, token, and key.
type Config struct {
	ModulePath string // e.g. /usr/local/lib/softhsm/libsofthsm2.so
	TokenLabel string // e.g. spt-issuer
	KeyLabel   string // label of the key pair, e.g. spt-issuer-cat
	PIN        string // user PIN (supply from env/secret, not source)
}

// Signer is a crypto.Signer whose Ed25519 private key lives inside a PKCS#11 token.
type Signer struct {
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	priv    pkcs11.ObjectHandle
	pub     ed25519.PublicKey
	mu      sync.Mutex // C_Sign on a session is not concurrency-safe
	closed  bool
}

// Open loads the module, logs into the token, and locates the key pair KeyLabel.
// Call Close when finished.
func Open(cfg Config) (*Signer, error) {
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("hsm: cannot load PKCS#11 module %q", cfg.ModulePath)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("hsm: initialize: %w", err)
	}
	slot, err := findSlot(ctx, cfg.TokenLabel)
	if err != nil {
		ctx.Destroy()
		return nil, err
	}
	sess, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("hsm: open session: %w", err)
	}
	if err := ctx.Login(sess, pkcs11.CKU_USER, cfg.PIN); err != nil {
		ctx.CloseSession(sess)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("hsm: login: %w", err)
	}
	priv, err := findObject(ctx, sess, cfg.KeyLabel, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}
	pubObj, err := findObject(ctx, sess, cfg.KeyLabel, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		return nil, err
	}
	pub, err := ed25519Public(ctx, sess, pubObj)
	if err != nil {
		return nil, err
	}
	return &Signer{ctx: ctx, session: sess, priv: priv, pub: pub}, nil
}

// Public implements crypto.Signer.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign implements crypto.Signer for pure Ed25519 via CKM_EDDSA. For Ed25519 the
// "digest" argument is the full message and opts must be crypto.Hash(0) — this
// exactly matches ed25519.PrivateKey.Sign, so callers written against
// crypto.Signer work with either an on-disk key or this HSM signer.
func (s *Signer) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("hsm: Ed25519 signs the message; expected opts=crypto.Hash(0)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("hsm: signer closed")
	}
	m := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEDDSA, nil)}
	if err := s.ctx.SignInit(s.session, m, s.priv); err != nil {
		return nil, fmt.Errorf("hsm: SignInit: %w", err)
	}
	sig, err := s.ctx.Sign(s.session, message)
	if err != nil {
		return nil, fmt.Errorf("hsm: Sign: %w", err)
	}
	return sig, nil
}

// Close logs out and releases the module.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	_ = s.ctx.Logout(s.session)
	_ = s.ctx.CloseSession(s.session)
	_ = s.ctx.Finalize()
	s.ctx.Destroy()
	return nil
}

func findSlot(ctx *pkcs11.Ctx, tokenLabel string) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("hsm: slot list: %w", err)
	}
	for _, slot := range slots {
		if ti, err := ctx.GetTokenInfo(slot); err == nil && ti.Label == tokenLabel {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("hsm: token %q not found", tokenLabel)
}

func findObject(ctx *pkcs11.Ctx, sess pkcs11.SessionHandle, label string, class uint) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := ctx.FindObjectsInit(sess, tmpl); err != nil {
		return 0, fmt.Errorf("hsm: FindObjectsInit: %w", err)
	}
	objs, _, err := ctx.FindObjects(sess, 1)
	_ = ctx.FindObjectsFinal(sess)
	if err != nil {
		return 0, fmt.Errorf("hsm: FindObjects: %w", err)
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("hsm: object label=%q class=%d not found", label, class)
	}
	return objs[0], nil
}

// ed25519Public reads CKA_EC_POINT and decodes it to an ed25519.PublicKey.
// PKCS#11 returns EC_POINT as a DER OCTET STRING wrapping the 32-byte point
// (e.g. 0x04 0x20 || 32 bytes); some tokens return the raw 32 bytes.
func ed25519Public(ctx *pkcs11.Ctx, sess pkcs11.SessionHandle, pub pkcs11.ObjectHandle) (ed25519.PublicKey, error) {
	attrs, err := ctx.GetAttributeValue(sess, pub, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("hsm: read EC_POINT: %w", err)
	}
	raw := attrs[0].Value
	var point []byte
	if _, uerr := asn1.Unmarshal(raw, &point); uerr != nil {
		point = raw // not DER-wrapped; use as-is
	}
	if len(point) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("hsm: unexpected Ed25519 point length %d", len(point))
	}
	return ed25519.PublicKey(point), nil
}
