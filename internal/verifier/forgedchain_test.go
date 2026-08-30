package verifier_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/dpop"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
)

// forgedChain rebuilds a CAT → CT… → SPT-Txn chain from a valid one, re-signing
// every level so that arbitrary claims can be changed and the chain still hangs
// together.
//
// # Why this exists
//
// Every guard the issuers enforce — a currency beside a monetary ceiling, a
// positive delegation depth, a canonical amount — makes the corresponding
// MALFORMED token unmintable through cattoken/cttoken/txntoken. That is the
// point of those guards, and it is also why the verifier-side test for the same
// property cannot be written with the real issuers: there is no longer a way to
// produce the input.
//
// The threat model is a NON-CONFORMING issuer: someone who holds a registered
// issuer key and does not run our code, or a token minted before a guard
// existed. Enforcement must not be the layer that trusts issuance got it right,
// so it has to be testable against exactly that input.
//
// # What it fixes for you
//
// Changing a claim breaks three bindings the verifier re-derives, and forgetting
// any one of them makes a test pass at the wrong step — which is worse than no
// test, because it reads as coverage. This builder recomputes all three, in
// order, from the root down:
//
//   - spt_parent_hash: SHA-256 of the compact bytes of the ACTUAL parent, so a
//     re-signed parent invalidates every descendant until it is recomputed.
//   - spt_cat_ref / spt_parent_ref: the jti linkage.
//   - the SPT-Txn's spt_ct_ref and its context hash.
//
// It deliberately does NOT re-mint through txntoken: that would re-apply the
// issuer's guards and defeat the purpose.
type forgedChain struct {
	t   *testing.T
	a   *agenticChain
	cat string
	cts []string
}

// newForgedChain starts from the valid chain the harness built.
func newForgedChain(t *testing.T, a *agenticChain) *forgedChain {
	t.Helper()
	return &forgedChain{t: t, a: a, cat: a.cat.Token, cts: []string{a.ctA.Token, a.ctB.Token}}
}

// mutate applies edits to the claims of the CAT (level -1) or a CT (level 0, 1,
// …) and re-signs the whole chain from that level down, restoring every binding.
// The key is signed with the same issuer key the real chain used at that level.
func (f *forgedChain) mutate(level int, edit func(claims map[string]any)) *forgedChain {
	f.t.Helper()

	if level == -1 {
		claims := decodeClaims(f.t, f.cat)
		edit(claims)
		f.cat = forgeToken(claims, f.catKey())
	} else {
		claims := decodeClaims(f.t, f.cts[level])
		edit(claims)
		f.cts[level] = forgeToken(claims, f.ctKey(level))
	}
	f.rebind()
	return f
}

// rebind re-derives every parent-dependent binding from the root down and
// re-signs each level whose parent changed underneath it.
func (f *forgedChain) rebind() {
	f.t.Helper()
	catClaims := decodeClaims(f.t, f.cat)
	catJTI := catClaims["jti"]

	parentToken := f.cat
	parentJTI := catJTI
	for i := range f.cts {
		claims := decodeClaims(f.t, f.cts[i])
		sum := sha256.Sum256([]byte(parentToken))
		claims["spt_parent_hash"] = base64.RawURLEncoding.EncodeToString(sum[:])
		claims["spt_cat_ref"] = catJTI
		if i > 0 {
			claims["spt_parent_ref"] = parentJTI
		}
		f.cts[i] = forgeToken(claims, f.ctKey(i))
		parentToken = f.cts[i]
		parentJTI = claims["jti"]
	}
}

// catKey and ctKey return the key the real chain used to sign each level, so a
// forged token still resolves against the registry.
func (f *forgedChain) catKey() ed25519.PrivateKey { return f.a.orgPriv }
func (f *forgedChain) ctKey(level int) ed25519.PrivateKey {
	if level == 0 {
		return f.a.orgPriv // hop 1 is issued by the org issuer
	}
	return f.a.ctaPriv // later hops are issued by agent A's delegation key
}

// txnFor mints an SPT-Txn against the FORGED leaf by re-signing a valid one, so
// the issuer's own guards are not re-applied. Returns the token and a matching
// DPoP proof.
func (f *forgedChain) txnFor(tc ledger.TxnContext) (string, string) {
	f.t.Helper()

	// Mint a valid SPT-Txn against the REAL leaf to get a well-formed claim set,
	// using a transaction the real issuer will accept.
	valid, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issTTS, Audience: aud, ParentCT: f.a.ctB.Token, ParentIssuerKey: f.a.ctaPub,
		HolderPublicKey: f.a.agentBPub, Ledger: f.a.l, Txn: paymentTxn("100"),
	}, f.a.ttsPriv)
	if err != nil {
		f.t.Fatalf("seed SPT-Txn: %v", err)
	}

	leafClaims := decodeClaims(f.t, f.cts[len(f.cts)-1])
	claims := decodeClaims(f.t, valid.Token)
	claims["spt_ct_ref"] = leafClaims["jti"]
	claims["human_anchor"] = leafClaims["human_anchor"]

	// Bind the token to the transaction the test actually presents. A forged
	// chain that skipped this would be denied at step 8 for the wrong reason.
	if _, hash, err := ledger.ContextHash(f.a.l, tc); err == nil {
		claims["spt_txn_context_hash"] = hash
	}

	token := forgeToken(claims, f.a.ttsPriv)
	proof, err := dpop.Proof(f.a.agentBPriv, htm, htu, dpop.ATH(token))
	if err != nil {
		f.t.Fatal(err)
	}
	return token, proof
}

// chain returns the CT chain in the shape verifier.Input wants.
func (f *forgedChain) chain() []string { return append([]string(nil), f.cts...) }
