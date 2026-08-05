package pqbench

// pqbench_test.go — post-quantum migration impact benchmarks.
//
// Measurement discipline (why each cost is isolated, not blended):
//   - SIGN and VERIFY are measured separately from KEYGEN, because the SPT-Txn
//     hot path does NOT generate a keypair per transaction — the holder key is
//     long-lived and only the JTI + signature rotate (see txntoken.Issue, which
//     takes HolderPublicKey as input). Keygen is reported on its own so a future
//     "fresh key per txn" model can be costed, but it is NOT in the per-txn total.
//   - Token WIRE SIZE is a static property (TestWireSizes), separate from latency.
//   - The REGISTRY cached lookup is measured to show it is microseconds and thus
//     not a latency bottleneck; the on-chain/cold sync is out-of-band and never in
//     the transaction path, so it is deliberately not counted in the hot path.
//   - PQ inflates sign, verify, and size; it does NOT inflate the cached registry
//     lookup. The escrow KEM is where PQ actually lands today (signatures are still
//     classical Ed25519 — ML-DSA is a modeled projection behind -tags mldsa_bench).
//
// Report the raw crypto (µs) AND, separately, the full token Issue/Verify
// (crypto + JSON + JTI). The deployed HTTP round-trip (TLS + relayd) is a further
// layer measured by cmd/loadbench, not here.

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/escrow"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
)

// ── shared fixtures ──────────────────────────────────────────────────────────

// chain builds a fresh CAT -> CT -> TXN using long-lived keys, exactly as the
// production issuers do (keys created once, reused per transaction). Returns the
// pieces the benchmarks need. Used at setup time (outside the timed loop).
type fixture struct {
	orgPub, orgPriv ed25519.PublicKey
	orgPrivKey      ed25519.PrivateKey
	ttsPub          ed25519.PublicKey
	ttsPriv         ed25519.PrivateKey
	agentPub        ed25519.PublicKey
	l               ledger.Ledger
	tc              ledger.TxnContext
	cat             *cattoken.CAT
	ct              *cttoken.CT
	txn             *txntoken.TXN
}

func newFixture(tb testing.TB) *fixture {
	tb.Helper()
	orgPub, orgPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	ttsPub, ttsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	agentPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	l, err := ledger.Get("xrpl")
	if err != nil {
		tb.Fatal(err)
	}
	tc := ledger.TxnContext{
		Chain: "xrpl", Originator: "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT",
		Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
		Amount:      "4000", Currency: "USD", Timestamp: 1750000000,
		Extra: map[string]string{"DestinationTag": "42"},
	}

	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: "did:web:org", Subject: "alice", PrincipalName: "alice",
		Scope:              cattoken.CapabilityScope{"action": "payment", "max_amount": 10000, "currency": "USD"},
		DelegationDepthMax: 3, TTL: time.Hour, HolderPublicKey: agentPub,
	}, orgPriv)
	if err != nil {
		tb.Fatalf("CAT: %v", err)
	}
	ct, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: "did:web:org", ParentCAT: cat.Token, ParentIssuerKey: orgPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: agentPub,
	}, orgPriv)
	if err != nil {
		tb.Fatalf("CT: %v", err)
	}
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: "did:web:tts", Audience: "https://api.example.com",
		ParentCT: ct.Token, ParentIssuerKey: orgPub,
		HolderPublicKey: agentPub, Ledger: l, Txn: tc,
	}, ttsPriv)
	if err != nil {
		tb.Fatalf("TXN: %v", err)
	}
	return &fixture{
		orgPub: orgPub, orgPriv: orgPub, orgPrivKey: orgPriv,
		ttsPub: ttsPub, ttsPriv: ttsPriv, agentPub: agentPub,
		l: l, tc: tc, cat: cat, ct: ct, txn: txn,
	}
}

// ── 1. Token hot path — Issue (classical Ed25519, current baseline) ──────────
// Issuance = 1 Ed25519 sign + JSON marshal + 16-byte JTI. No keygen (holder key
// is long-lived). This is the honest per-transaction mint cost.

func BenchmarkTXN_Issue(b *testing.B) {
	f := newFixture(b)
	req := txntoken.IssueRequest{
		Issuer: "did:web:tts", Audience: "https://api.example.com",
		ParentCT: f.ct.Token, ParentIssuerKey: f.orgPub,
		HolderPublicKey: f.agentPub, Ledger: f.l, Txn: f.tc,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := txntoken.Issue(req, f.ttsPriv); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCT_Issue(b *testing.B) {
	f := newFixture(b)
	req := cttoken.IssueRequest{
		Issuer: "did:web:org", ParentCAT: f.cat.Token, ParentIssuerKey: f.orgPub,
		RequestedScope:  tbac.Scope{"max_amount": 8000, "currency": "USD"},
		HolderPublicKey: f.agentPub,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cttoken.Issue(req, f.orgPrivKey); err != nil {
			b.Fatal(err)
		}
	}
}

// ── 2. Token hot path — Verify (per-token crypto + JSON parse) ───────────────
// This is the dominant cost of the verifier's crypto steps. The full eight-step
// engine (verifier.Engine.Verify) adds scope/depth/registry/DPoP checks on top;
// benchmark that separately if you want the whole engine, but the signature
// verification measured here is the part PQ changes.

func BenchmarkTXN_Verify(b *testing.B) {
	f := newFixture(b)
	tok := f.txn.Token
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := txntoken.Verify(tok, f.ttsPub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCAT_Verify(b *testing.B) {
	f := newFixture(b)
	tok := f.cat.Token
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cattoken.Verify(tok, f.orgPub); err != nil {
			b.Fatal(err)
		}
	}
}

// ── 3. Raw signature primitive (isolates crypto from JSON plumbing) ──────────

func BenchmarkEd25519_Sign(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := make([]byte, 256) // representative signing-input size
	rand.Read(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(priv, msg)
	}
}

func BenchmarkEd25519_Verify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := make([]byte, 256)
	rand.Read(msg)
	sig := ed25519.Sign(priv, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !ed25519.Verify(pub, msg, sig) {
			b.Fatal("verify failed")
		}
	}
}

// ── 4. KEYGEN — measured separately (NOT in the per-transaction hot path) ────
// Reported on its own so a hypothetical per-txn-keygen model can be costed. PQ
// keygen (ML-KEM) is meaningfully heavier than Ed25519/X25519; this is where you
// see it.

func BenchmarkKeygen_Ed25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, _, err := ed25519.GenerateKey(rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeygen_X25519(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := ecdh.X25519().GenerateKey(rand.Reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeygen_MLKEM768(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := mlkem.GenerateKey768(); err != nil {
			b.Fatal(err)
		}
	}
}

// ── 5. KEM cost — classical X25519 vs hybrid X25519+ML-KEM-768 ───────────────
// This is the escrow's confidentiality path — the ONLY place PQ is live today.
// Encap = the Seal side; Decap = the Open side. Compare classical vs hybrid to
// quantify the migration delta.

func BenchmarkKEM_Classical_Encap(b *testing.B) {
	recipient, _ := ecdh.X25519().GenerateKey(rand.Reader)
	rpub := recipient.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
		if _, err := eph.ECDH(rpub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKEM_Hybrid_Encap(b *testing.B) {
	recipient, _ := ecdh.X25519().GenerateKey(rand.Reader)
	rpub := recipient.PublicKey()
	dk, _ := mlkem.GenerateKey768()
	ek := dk.EncapsulationKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
		if _, err := eph.ECDH(rpub); err != nil {
			b.Fatal(err)
		}
		_, _ = ek.Encapsulate() // ML-KEM shared secret + 1088B ciphertext
	}
}

func BenchmarkKEM_Hybrid_Decap(b *testing.B) {
	dk, _ := mlkem.GenerateKey768()
	ek := dk.EncapsulationKey()
	_, ct := ek.Encapsulate()
	recipient, _ := ecdh.X25519().GenerateKey(rand.Reader)
	rpub := recipient.PublicKey()
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	ephPub := eph.PublicKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := recipient.ECDH(ephPub); err != nil { // X25519 half
			b.Fatal(err)
		}
		if _, err := dk.Decapsulate(ct); err != nil { // ML-KEM half
			b.Fatal(err)
		}
		_ = rpub
	}
}

// ── 6. Full escrow envelope — deployed hybrid Seal/Open (crypto + AEAD) ───────

func BenchmarkEscrow_Seal_Hybrid(b *testing.B) {
	k, err := escrow.NewEscrowKey()
	if err != nil {
		b.Fatal(err)
	}
	pub := k.PublicKey()
	identity := make([]byte, 256) // representative sealed identity material
	rand.Read(identity)
	iat := time.Now().Unix()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := escrow.Seal(identity, pub, "anchor-abc", "did:web:issuer", iat); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEscrow_Open_Hybrid(b *testing.B) {
	k, err := escrow.NewEscrowKey()
	if err != nil {
		b.Fatal(err)
	}
	pub := k.PublicKey()
	identity := make([]byte, 256)
	rand.Read(identity)
	iat := time.Now().Unix()
	env, err := escrow.Seal(identity, pub, "anchor-abc", "did:web:issuer", iat)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := env.Open(k); err != nil {
			b.Fatal(err)
		}
	}
}

// ── 7. Trust-registry cached lookup — proves it is NOT in the latency path ───
// The MockRegistry is an in-memory map (the "hot" cached read). The on-chain /
// cold sync is out-of-band and never per-transaction, so it is intentionally not
// benchmarked as a hot-path cost.

func BenchmarkRegistry_LookupCached(b *testing.B) {
	reg, err := trustregistry.NewMockRegistry("")
	if err != nil {
		b.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ctx := context.Background()
	if err := reg.Register(ctx, &trustregistry.Record{
		Iss: "did:web:org", Role: trustregistry.RoleCTIssuer, PublicKey: pub, KeyType: "Ed25519",
		ValidFrom: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour),
		Status: trustregistry.StatusActive,
	}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := reg.Lookup(ctx, "did:web:org", trustregistry.RoleCTIssuer); err != nil {
			b.Fatal(err)
		}
	}
}

// ── 8. Wire sizes (static; run: go test -run TestWireSizes -v) ───────────────
// Token size is the on-wire property PQ inflates. The point to demonstrate: the
// signing path stays classical, so the three-token chain stays small; the hybrid
// KEM cost lands ONLY on the escrow envelope, which is off the hot path.

func TestWireSizes(t *testing.T) {
	f := newFixture(t)
	t.Logf("token wire sizes (classical Ed25519 signing):")
	t.Logf("  CAT   = %d bytes", len(f.cat.Token))
	t.Logf("  CT    = %d bytes", len(f.ct.Token))
	t.Logf("  TXN   = %d bytes  (the ~30s leaf, hot path)", len(f.txn.Token))
	t.Logf("  chain (CAT+CT+TXN) = %d bytes", len(f.cat.Token)+len(f.ct.Token)+len(f.txn.Token))

	k, err := escrow.NewEscrowKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey()
	env, err := escrow.Seal(make([]byte, 256), pub, "anchor", "iss", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("escrow (hybrid X25519+ML-KEM-768, OFF the token hot path):")
	t.Logf("  escrow public key  = %d B X25519 + %d B ML-KEM encap", len(pub.X25519Bytes()), len(pub.MlkemEncapKeyBytes()))
	t.Logf("  escrow private key = %d bytes", len(k.Bytes()))
	t.Logf("  envelope ephemeral X25519 pub = %d bytes", len(env.EphemeralPub))
	t.Logf("  envelope ML-KEM ciphertext    = %d bytes", len(env.KemCiphertext))
	t.Logf("  envelope AES-GCM nonce+ct     = %d + %d bytes", len(env.Nonce), len(env.Ciphertext))
}
