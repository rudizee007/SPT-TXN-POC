// Package cttoken implements Capability Token (CT) issuance for the SPT-Txn
// POC — Milestone 3.
//
// A Capability Token is a scope-attenuated child of a Compliance Attestation
// Token (CAT, see internal/cattoken). Per Section 3.4 of
// draft-coetzee-oauth-spt-txn-tokens, the issuer:
//
//  1. verifies the parent CAT signature and basic claims,
//  2. checks the requested scope is contained within the CAT's capability_scope
//     (internal/tbac), and
//  3. issues a CT that carries the humanAnchor forward unchanged, decrements
//     the remaining delegation depth, and references the parent CAT.
//
// Token structure (JWT claims):
//
//	{
//	  "iss":                       string,   // ct_issuer identifier
//	  "sub":                       string,   // subject, carried from the CAT
//	  "iat":                       int64,
//	  "exp":                       int64,
//	  "jti":                       string,
//	  "txn_token_type":            "CT",
//	  "human_anchor":              string,   // propagated unchanged from the CAT
//	  "capability_scope":          object,   // attenuated scope (<= parent)
//	  "delegation_depth_remaining": int,     // parent max - 1
//	  "holder_key":                string,   // hex Ed25519 key of this holder
//	  "spt_cat_ref":               string,   // parent CAT jti
//	  "spt_parent_hash":           string,   // base64url(SHA-256(parent CAT))
//	}
//
// Signed with Ed25519 (alg EdDSA). The signing key is the registered
// ct_issuer key (Role ct_issuer also signs CATs — same role, Section 8.1).
// Standard library only.
package cttoken

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

// DefaultTTL is the Capability Token lifetime when IssueRequest.TTL is zero.
// CTs are short-lived relative to CATs but longer-lived than SPT-Txn Tokens.
const DefaultTTL = 10 * time.Minute

// IssueRequest is the input to the Capability Token issuer.
type IssueRequest struct {
	// Issuer is the registered ct_issuer identifier (Trust Registry).
	Issuer string

	// ParentCAT is the compact JWT of the parent Compliance Attestation Token.
	ParentCAT string

	// ParentIssuerKey is the public key the parent CAT was signed with. In the
	// running service this comes from a Trust Registry lookup for
	// (CAT.iss, role=ct_issuer).
	ParentIssuerKey ed25519.PublicKey

	// RequestedScope is the (narrower) scope the holder is requesting. It MUST
	// be contained within the parent CAT's capability_scope.
	RequestedScope tbac.Scope

	// HolderPublicKey is the Ed25519 key bound to this Capability Token. It may
	// be the same agent key as the CAT holder, or a delegated subkey.
	HolderPublicKey ed25519.PublicKey

	// TTL overrides DefaultTTL when non-zero.
	TTL time.Duration

	// NotBefore, when set, opens this CT's validity window at that instant (an
	// absolute nbf claim). Zero leaves the token valid from issuance. Used to
	// place a sub-band inside a period -- a $3 day inside a $100 month.
	NotBefore time.Time

	// Status optionally sets the signed `status` claim binding this CT to a
	// Token Status List entry for scalable per-token revocation
	// (docs/spec/STATUS-LIST.md §4). nil leaves the CT out of status scope.
	Status map[string]any

	// Subband, when set, marks this CT as slice LegIndex of its parent CAT's
	// committed group root (§7.2). IssueSubbands sets it; the verifier requires
	// these claims on any CT that carries a max_cumulative budget and checks the
	// membership against the parent's subband_group_root.
	Subband *SubbandMembership
}

// SubbandMembership is a slice CT's proof that it is one member of its parent's
// committed group root: the leg index and Merkle path, plus the root, size and
// hash suite it is a member of. Built from tbac.CommitBandDivision output.
type SubbandMembership struct {
	GroupRoot  [32]byte
	GroupSize  uint32
	HashSuite  tbac.HashSuite
	LegIndex   uint32
	MerklePath [][32]byte
}

// CT is an issued Capability Token.
type CT struct {
	Token       string
	HumanAnchor string // hex humanAnchor, propagated from the parent CAT
	Claims      map[string]any
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// Issue verifies the parent CAT, attenuates scope, and signs a Capability
// Token. signingKey is the ct_issuer Ed25519 private key.
func Issue(req IssueRequest, signingKey crypto.Signer) (*CT, error) {
	if req.Issuer == "" {
		return nil, fmt.Errorf("issuer required")
	}
	if len(req.HolderPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("holder public key must be %d bytes", ed25519.PublicKeySize)
	}
	if req.RequestedScope == nil {
		return nil, fmt.Errorf("requested scope required")
	}

	// ── 1. Verify the parent CAT ──────────────────────────────────────
	parent, err := cattoken.Verify(req.ParentCAT, req.ParentIssuerKey)
	if err != nil {
		return nil, fmt.Errorf("parent CAT invalid: %w", err)
	}

	// ── 2. Extract parent fields ──────────────────────────────────────
	parentScopeRaw, ok := parent["capability_scope"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parent CAT missing capability_scope")
	}
	parentScope := tbac.Scope(parentScopeRaw)

	humanAnchor, ok := parent["human_anchor"].(string)
	if !ok || humanAnchor == "" {
		return nil, fmt.Errorf("parent CAT missing human_anchor")
	}
	sub, _ := parent["sub"].(string)
	parentJTI, _ := parent["jti"].(string)

	// delegation_depth_max arrives as float64 after JSON decoding.
	depthMaxF, ok := parent["delegation_depth_max"].(float64)
	if !ok {
		return nil, fmt.Errorf("parent CAT missing delegation_depth_max")
	}
	remaining := int(depthMaxF) - 1
	if remaining < 0 {
		return nil, fmt.Errorf("delegation depth exhausted: parent permits no further delegation")
	}

	// ── 3. Attenuate scope (containment check) ────────────────────────
	// A budgeted parent (declares max_cumulative, or committed a division) may
	// only delegate committed slices, and those are minted by IssueSubbands.
	// An ordinary child would drop the cumulative dimension — containment
	// permits dropping — and inherit the whole budget as a per-transaction
	// ceiling with no count. The verifier refuses such a chain at step 6 (the
	// enforcement); refusing here too means the token never exists (hygiene).
	_, committed := parent["subband_group_root"]
	if (tbac.DeclaresCumulativeBudget(parentScope) || committed) && req.Subband == nil {
		return nil, fmt.Errorf("parent CAT holds a cumulative budget: only committed sub-band slices may be delegated from it (IssueSubbands); an ordinary CT would inherit the budget uncounted")
	}
	attenuated, err := tbac.Attenuate(parentScope, req.RequestedScope)
	if err != nil {
		return nil, err
	}
	// Containment permits a child to DROP a dimension the parent declared, and for
	// `currency` that is a legitimate narrowing request: the delegator asks for a
	// lower amount and says nothing about the unit. Sealing it as asked would
	// leave a token whose ceiling reads as a bound in every currency at once, so
	// carry the parent's unit down with the ceiling -- a strict narrowing, since
	// the value comes from the parent -- and then refuse to mint anything that is
	// still unqualified. See tbac.InheritMoneyUnit and tbac.ValidateIssuance.
	attenuated, err = tbac.InheritMoneyUnit(parentScope, attenuated)
	if err != nil {
		return nil, fmt.Errorf("attenuated scope: %w", err)
	}
	if err := tbac.ValidateIssuance(attenuated); err != nil {
		return nil, fmt.Errorf("attenuated scope: %w", err)
	}

	// ── 4. Build claims ───────────────────────────────────────────────
	now := time.Now().UTC()
	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	exp := now.Add(ttl)
	// TTL monotonicity (docs/spec/DELEGATION-INTENT-MCP.md §1.2): the child's
	// validity window must sit inside the parent's. The DEFAULT lifetime
	// clamps to the parent boundary (a default is computed, not requested);
	// an EXPLICITLY requested TTL that would outlive the parent is rejected —
	// the issuer never silently rewrites an explicit request.
	parentExpF, ok := parent["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("parent CAT missing exp")
	}
	parentExp := int64(parentExpF)
	if req.TTL == 0 && exp.Unix() > parentExp {
		exp = time.Unix(parentExp, 0).UTC()
	}
	if exp.Unix() > parentExp {
		return nil, fmt.Errorf("child CT would outlive parent CAT (child exp %d > parent exp %d): TTL must attenuate", exp.Unix(), parentExp)
	}
	jti, err := newJTI()
	if err != nil {
		return nil, fmt.Errorf("generate jti: %w", err)
	}
	parentHash := sha256.Sum256([]byte(req.ParentCAT))

	claims := map[string]any{
		"iss":                        req.Issuer,
		"sub":                        sub,
		"iat":                        now.Unix(),
		"exp":                        exp.Unix(),
		"jti":                        jti,
		"txn_token_type":             "CT",
		"human_anchor":               humanAnchor,
		"capability_scope":           map[string]any(attenuated),
		"delegation_depth_remaining": remaining,
		"holder_key":                 hex.EncodeToString(req.HolderPublicKey),
		"spt_cat_ref":                parentJTI,
		"spt_parent_hash":            base64url(parentHash[:]),
	}

	// nbf (not-before): open this CT's window, the mirror of exp -- child.nbf >=
	// parent.nbf, as child.exp <= parent.exp. See attenuateNotBefore.
	nbf, err := attenuateNotBefore(parent, req.NotBefore, exp.Unix())
	if err != nil {
		return nil, err
	}
	if nbf > 0 {
		claims["nbf"] = nbf
	}

	// §7.2: slice membership, when this CT is a sub-band of its parent's committed
	// group root. The verifier rebuilds the leaf from this CT's scope + window +
	// these claims and checks membership against the parent's subband_group_root.
	if req.Subband != nil {
		if req.Subband.GroupSize == 0 || req.Subband.LegIndex >= req.Subband.GroupSize {
			return nil, fmt.Errorf("subband leg index %d out of range for group size %d", req.Subband.LegIndex, req.Subband.GroupSize)
		}
		if !tbac.IsKnownHashSuite(req.Subband.HashSuite) {
			return nil, fmt.Errorf("subband hash suite %q is not known", req.Subband.HashSuite)
		}
		claims["subband_group_root"] = hex.EncodeToString(req.Subband.GroupRoot[:])
		claims["subband_group_size"] = req.Subband.GroupSize
		claims["subband_hash_suite"] = string(req.Subband.HashSuite)
		claims["subband_leg_index"] = req.Subband.LegIndex
		mp := make([]string, len(req.Subband.MerklePath))
		for i, h := range req.Subband.MerklePath {
			mp[i] = hex.EncodeToString(h[:])
		}
		claims["subband_merkle_path"] = mp
	}

	if req.Status != nil {
		claims["status"] = req.Status
	}

	token, err := signJWT(claims, signingKey)
	if err != nil {
		return nil, err
	}

	return &CT{
		Token:       token,
		HumanAnchor: humanAnchor,
		Claims:      claims,
		IssuedAt:    now,
		ExpiresAt:   exp,
	}, nil
}

// SubbandIssueRequest divides a parent CAT's committed max_cumulative budget into
// its N slices and mints each as a member CT. The bands MUST reproduce the CAT's
// signed subband_group_root, or issuance is refused — a caller cannot mint slices
// for a division the human's authority did not commit.
type SubbandIssueRequest struct {
	Issuer          string
	ParentCAT       string
	ParentIssuerKey ed25519.PublicKey
	HashSuite       tbac.HashSuite
	// DivisionNbf, DivisionExp are the window the division was committed under —
	// the SAME [nbf, exp) the caller passed to tbac.CommitBandDivision to produce
	// the CAT's subband_group_root. Passed explicitly (not derived from the CAT's
	// token exp) so the recomputed root reproduces the committed one deterministically.
	DivisionNbf int64
	DivisionExp int64
	// Bands are the N slices: each carries its max_cumulative portion + currency
	// and its [NotBefore, Expiry) window in Unix seconds, inside DivisionNbf..DivisionExp.
	Bands []tbac.Band
	// HolderPublicKeys binds each slice to a holder key: one per band, or a single
	// key reused for every slice.
	HolderPublicKeys []ed25519.PublicKey
}

// IssueSubbands verifies the parent CAT, recomputes the division commitment from
// the bands and checks it equals the CAT's committed root, then mints each slice
// as a CT carrying its membership proof. All-or-nothing: any failure returns no
// tokens.
func IssueSubbands(req SubbandIssueRequest, signingKey crypto.Signer) ([]*CT, error) {
	parent, err := cattoken.Verify(req.ParentCAT, req.ParentIssuerKey)
	if err != nil {
		return nil, fmt.Errorf("parent CAT invalid: %w", err)
	}
	parentScopeRaw, ok := parent["capability_scope"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parent CAT missing capability_scope")
	}
	parentScope := tbac.Scope(parentScopeRaw)

	committedRoot, ok := parent["subband_group_root"].(string)
	if !ok || committedRoot == "" {
		return nil, fmt.Errorf("parent CAT carries no subband_group_root: its budget is not committed for division")
	}
	root, _, paths, err := tbac.CommitBandDivision(req.HashSuite, parentScope, req.DivisionNbf, req.DivisionExp, req.Bands)
	if err != nil {
		return nil, fmt.Errorf("recompute division: %w", err)
	}
	if hex.EncodeToString(root[:]) != committedRoot {
		return nil, fmt.Errorf("bands do not reproduce the CAT's committed group root")
	}
	if len(req.HolderPublicKeys) != len(req.Bands) && len(req.HolderPublicKeys) != 1 {
		return nil, fmt.Errorf("holder keys (%d) must match bands (%d), or supply one shared key", len(req.HolderPublicKeys), len(req.Bands))
	}

	n := uint32(len(req.Bands))
	slices := make([]*CT, len(req.Bands))
	for i, band := range req.Bands {
		holder := req.HolderPublicKeys[0]
		if len(req.HolderPublicKeys) == len(req.Bands) {
			holder = req.HolderPublicKeys[i]
		}
		var groot [32]byte
		copy(groot[:], root[:])
		ct, err := Issue(IssueRequest{
			Issuer:          req.Issuer,
			ParentCAT:       req.ParentCAT,
			ParentIssuerKey: req.ParentIssuerKey,
			RequestedScope:  band.Scope,
			HolderPublicKey: holder,
			NotBefore:       time.Unix(band.NotBefore, 0).UTC(),
			TTL:             time.Until(time.Unix(band.Expiry, 0)),
			Subband: &SubbandMembership{
				GroupRoot:  groot,
				GroupSize:  n,
				HashSuite:  req.HashSuite,
				LegIndex:   uint32(i),
				MerklePath: paths[i],
			},
		}, signingKey)
		if err != nil {
			return nil, fmt.Errorf("mint slice %d: %w", i, err)
		}
		slices[i] = ct
	}
	return slices, nil
}

// DelegateRequest is the input to CT→CT delegation (Milestone 7, agentic
// authorization). An agent that holds a Capability Token hands a strictly
// narrower capability to a sub-agent or tool. Unlike IssueRequest (whose parent
// is a CAT), the parent here is itself a CT, so the chain can extend to multiple
// hops while remaining monotonically attenuating and depth-bounded.
type DelegateRequest struct {
	// Issuer is the registered ct_issuer identifier signing THIS delegation. In
	// a multi-agent deployment the delegating party is itself a registered
	// issuer, so revoking its key collapses every capability it delegated
	// downstream without touching its own parent capability.
	Issuer string

	// ParentCT is the compact JWT of the parent Capability Token.
	ParentCT string

	// ParentIssuerKey is the public key the parent CT was signed with. In the
	// running service this comes from a Trust Registry lookup for
	// (parentCT.iss, role=ct_issuer).
	ParentIssuerKey ed25519.PublicKey

	// RequestedScope is the (narrower) scope for the sub-agent. It MUST be
	// contained within the parent CT's capability_scope.
	RequestedScope tbac.Scope

	// HolderPublicKey is the Ed25519 key of the sub-agent this CT is bound to.
	HolderPublicKey ed25519.PublicKey

	// TTL overrides DefaultTTL when non-zero. A delegated CT SHOULD NOT outlive
	// its parent; callers SHOULD pass a TTL no longer than the parent's
	// remaining life.
	TTL time.Duration

	// NotBefore, when set, opens this child's window; it must not precede the
	// parent CT's opening (attenuateNotBefore). Zero inherits the parent's.
	NotBefore time.Time

	// Status optionally sets the signed `status` claim binding this child CT
	// to a Token Status List entry (docs/spec/STATUS-LIST.md §4).
	Status map[string]any
}

// Delegate verifies the parent CT, attenuates its scope, decrements the
// remaining delegation depth, and signs a child Capability Token bound to the
// sub-agent's key. signingKey is the delegating ct_issuer's Ed25519 private key.
//
// The child commits to its immediate parent by hash (spt_parent_hash) and by
// jti (spt_parent_ref), and carries the root CAT reference (spt_cat_ref) and the
// humanAnchor forward unchanged, so a verifier can re-walk the whole chain
// offline from the root CAT to the leaf without contacting any issuer.
func Delegate(req DelegateRequest, signingKey crypto.Signer) (*CT, error) {
	if req.Issuer == "" {
		return nil, fmt.Errorf("issuer required")
	}
	if len(req.HolderPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("holder public key must be %d bytes", ed25519.PublicKeySize)
	}
	if req.RequestedScope == nil {
		return nil, fmt.Errorf("requested scope required")
	}

	// ── 1. Verify the parent CT ───────────────────────────────────────
	parent, err := Verify(req.ParentCT, req.ParentIssuerKey)
	if err != nil {
		return nil, fmt.Errorf("parent CT invalid: %w", err)
	}

	// ── 2. Extract parent fields ──────────────────────────────────────
	parentScopeRaw, ok := parent["capability_scope"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parent CT missing capability_scope")
	}
	parentScope := tbac.Scope(parentScopeRaw)

	humanAnchor, ok := parent["human_anchor"].(string)
	if !ok || humanAnchor == "" {
		return nil, fmt.Errorf("parent CT missing human_anchor")
	}
	sub, _ := parent["sub"].(string)
	parentJTI, _ := parent["jti"].(string)
	// Root CAT reference, propagated unchanged down every hop so the leaf still
	// names the human's root authority.
	rootCATRef, _ := parent["spt_cat_ref"].(string)

	// delegation_depth_remaining arrives as float64 after JSON decoding.
	remF, ok := parent["delegation_depth_remaining"].(float64)
	if !ok {
		return nil, fmt.Errorf("parent CT missing delegation_depth_remaining")
	}
	remaining := int(remF) - 1
	if remaining < 0 {
		return nil, fmt.Errorf("delegation depth exhausted: parent CT permits no further delegation")
	}

	// ── 3. Attenuate scope (containment check) ────────────────────────
	// A budgeted parent (declares max_cumulative, or committed a division) may
	// only delegate committed slices, and those are minted by IssueSubbands.
	// An ordinary child would drop the cumulative dimension — containment
	// permits dropping — and inherit the whole budget as a per-transaction
	// ceiling with no count. The verifier refuses such a chain at step 6 (the
	// enforcement); refusing here too means the token never exists (hygiene).
	// A slice (a CT carrying a cumulative budget) cannot be sub-divided through
	// this path: there is no SubbandMembership on a DelegateRequest, so any child
	// minted here would be an ordinary CT inheriting the slice's budget uncounted.
	// Refused. Sub-dividing a slice needs its own committed division and is not
	// built; the verifier refuses the chain regardless (step 6).
	_, committed := parent["subband_group_root"]
	if tbac.DeclaresCumulativeBudget(parentScope) || committed {
		return nil, fmt.Errorf("parent CT holds a cumulative budget: it cannot delegate an ordinary child, which would inherit the budget uncounted; sub-dividing a slice is not supported")
	}
	attenuated, err := tbac.Attenuate(parentScope, req.RequestedScope)
	if err != nil {
		return nil, err
	}
	// Containment permits a child to DROP a dimension the parent declared, and for
	// `currency` that is a legitimate narrowing request: the delegator asks for a
	// lower amount and says nothing about the unit. Sealing it as asked would
	// leave a token whose ceiling reads as a bound in every currency at once, so
	// carry the parent's unit down with the ceiling -- a strict narrowing, since
	// the value comes from the parent -- and then refuse to mint anything that is
	// still unqualified. See tbac.InheritMoneyUnit and tbac.ValidateIssuance.
	attenuated, err = tbac.InheritMoneyUnit(parentScope, attenuated)
	if err != nil {
		return nil, fmt.Errorf("attenuated scope: %w", err)
	}
	if err := tbac.ValidateIssuance(attenuated); err != nil {
		return nil, fmt.Errorf("attenuated scope: %w", err)
	}

	// ── 4. Build claims ───────────────────────────────────────────────
	now := time.Now().UTC()
	ttl := req.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	exp := now.Add(ttl)
	// TTL monotonicity (docs/spec/DELEGATION-INTENT-MCP.md §1.2): a delegated
	// CT must not outlive its parent CT. The default lifetime clamps to the
	// parent boundary; an explicitly requested TTL that overruns is rejected.
	parentExpF, ok := parent["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("parent CT missing exp")
	}
	parentExp := int64(parentExpF)
	if req.TTL == 0 && exp.Unix() > parentExp {
		exp = time.Unix(parentExp, 0).UTC()
	}
	if exp.Unix() > parentExp {
		return nil, fmt.Errorf("delegated CT would outlive parent CT (child exp %d > parent exp %d): TTL must attenuate", exp.Unix(), parentExp)
	}
	jti, err := newJTI()
	if err != nil {
		return nil, fmt.Errorf("generate jti: %w", err)
	}
	parentHash := sha256.Sum256([]byte(req.ParentCT))

	claims := map[string]any{
		"iss":                        req.Issuer,
		"sub":                        sub,
		"iat":                        now.Unix(),
		"exp":                        exp.Unix(),
		"jti":                        jti,
		"txn_token_type":             "CT",
		"human_anchor":               humanAnchor,
		"capability_scope":           map[string]any(attenuated),
		"delegation_depth_remaining": remaining,
		"holder_key":                 hex.EncodeToString(req.HolderPublicKey),
		"spt_cat_ref":                rootCATRef,               // root CAT, unchanged
		"spt_parent_ref":             parentJTI,                // immediate parent CT
		"spt_parent_hash":            base64url(parentHash[:]), // hash of immediate parent
	}

	// nbf (not-before): open this child's window, the mirror of exp.
	nbf, err := attenuateNotBefore(parent, req.NotBefore, exp.Unix())
	if err != nil {
		return nil, err
	}
	if nbf > 0 {
		claims["nbf"] = nbf
	}

	if req.Status != nil {
		claims["status"] = req.Status
	}

	token, err := signJWT(claims, signingKey)
	if err != nil {
		return nil, err
	}

	return &CT{
		Token:       token,
		HumanAnchor: humanAnchor,
		Claims:      claims,
		IssuedAt:    now,
		ExpiresAt:   exp,
	}, nil
}

// attenuateNotBefore computes a child's not-before (nbf) from an optionally
// requested window opening, enforcing that the child does not open before its
// parent. It is the mirror of the exp rule: exp bounds when validity ENDS
// (child.exp <= parent.exp); nbf bounds when it BEGINS (child.nbf >= parent.nbf).
//
// A parent with no nbf has no opening bound of its own -- it was valid from
// issuance -- so parentNbf is 0 and a child may introduce an opening. That is how
// a sub-band day-window is placed inside a month-long parent
// (VELOCITY-AND-CUMULATIVE-SPEND-DESIGN sec 3a). A child requesting no opening
// inherits the parent's, so it never becomes valid ahead of a not-yet-open
// parent. Returns 0 when there is no opening bound (valid from issuance, the
// prior behaviour); childExp is the already-attenuated expiry, used to reject an
// empty window (an opening at or after the expiry).
func attenuateNotBefore(parent map[string]any, requested time.Time, childExp int64) (int64, error) {
	var parentNbf int64
	if raw, present := parent["nbf"]; present {
		pn, ok := raw.(float64)
		if !ok || math.IsNaN(pn) || math.IsInf(pn, 0) || pn < math.MinInt64 || pn >= math.MaxInt64 {
			return 0, fmt.Errorf("parent has a present but non-numeric or out-of-range nbf (%v): its window cannot be evaluated and is denied, never skipped", raw)
		}
		parentNbf = int64(pn)
	}
	var nbf int64
	if requested.IsZero() {
		nbf = parentNbf
	} else {
		nbf = requested.UTC().Unix()
		if nbf < parentNbf {
			return 0, fmt.Errorf("child CT would open before its parent (child nbf %d < parent nbf %d): an opening must not precede the parent's", nbf, parentNbf)
		}
	}
	if nbf > 0 && nbf >= childExp {
		return 0, fmt.Errorf("child CT window is empty (nbf %d >= exp %d): the opening must precede the expiry", nbf, childExp)
	}
	return nbf, nil
}

// Verify checks the signature and basic claims of a Capability Token. Like
// cattoken.Verify it does not consult the Trust Registry — that is the
// verifier's job (M5).
func Verify(tokenStr string, issuerPublicKey ed25519.PublicKey) (map[string]any, error) {
	claims, err := verifyJWT(tokenStr, issuerPublicKey)
	if err != nil {
		return nil, err
	}
	if tt, _ := claims["txn_token_type"].(string); tt != "CT" {
		return nil, fmt.Errorf("expected txn_token_type=CT, got %q", tt)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing exp claim")
	}
	// RFC 7519: valid only while now < exp; expired once now >= exp.
	if time.Now().Unix() >= int64(exp) {
		return nil, fmt.Errorf("token expired")
	}
	return claims, nil
}

// ── shared JWT helpers (EdDSA, stdlib) ───────────────────────────────────────

func signJWT(claims map[string]any, key crypto.Signer) (string, error) {
	header := map[string]string{"alg": "EdDSA", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64url(headerJSON) + "." + base64url(claimsJSON)
	sig, err := key.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0))
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64url(sig), nil
}

func verifyJWT(tokenStr string, pub ed25519.PublicKey) (map[string]any, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}
	if hb, err := base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	} else {
		var h struct {
			Alg string `json:"alg"`
		}
		_ = json.Unmarshal(hb, &h)
		if h.Alg != "EdDSA" {
			return nil, fmt.Errorf("unexpected JWT alg %q, want EdDSA", h.Alg)
		}
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, fmt.Errorf("signature verification failed")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	return claims, nil
}

func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
