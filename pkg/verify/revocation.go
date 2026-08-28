package verify

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/statuslist"
)

// StatusList is a signed Status List Token plus what a verifier needs to check
// it: the URI it is bound to, and the issuer key it was signed under.
//
// The token is verified when it is installed, not when a decision is made. That
// is deliberate — status-list distribution belongs on the snapshot path, and the
// hot path should do a bitmap lookup, not a signature check.
type StatusList struct {
	// Token is the signed Status List Token (a JWT).
	Token string
	// URI is the status_list URI the token is bound to. A token whose `sub`
	// does not match is refused: it is somebody else's list.
	URI string
	// Key is the status-list issuer's ed25519 public key.
	Key ed25519.PublicKey
}

// EnableRevocation installs verified status lists and turns revocation checking
// ON for this verifier.
//
// Until this is called, a token carrying a `status` claim verifies WITHOUT its
// revocation status being checked. The engine treats an absent resolver as
// "not in scope for status-list revocation", which is right for a deployment
// that does not use status lists and wrong — silently — for one that does.
//
// It was previously impossible to call anything equivalent through this package.
// The engine field existed, the status-list implementation was complete and
// tested, and the only thing that ever set it was cmd/spt-demo: every embedder
// using the public API, including the reference gateway, ran with revocation off
// and no way to turn it on. That is what this fixes.
//
// Once enabled, the posture is fail-closed in the way the design intends: a
// token whose list is not cached, or whose cached list is stale, is DENIED as
// UNAVAILABLE rather than allowed. "My revocation feed stopped" and "this token
// is revoked" are different failures and the engine reports them differently,
// but neither is an allow.
//
// now is the evaluation time for the install-time signature and expiry checks;
// pass the zero Time for time.Now().
func (v *Verifier) EnableRevocation(now time.Time, lists ...StatusList) error {
	if len(lists) == 0 {
		return fmt.Errorf("verify: EnableRevocation needs at least one status list; " +
			"enabling it with none would deny every token that carries a status claim")
	}
	if now.IsZero() {
		now = time.Now()
	}
	res := statuslist.NewResolver()
	for i, l := range lists {
		if l.URI == "" {
			return fmt.Errorf("verify: status list %d has no URI", i)
		}
		if len(l.Key) != ed25519.PublicKeySize {
			return fmt.Errorf("verify: status list %d (%s): key is %d bytes, want %d",
				i, l.URI, len(l.Key), ed25519.PublicKeySize)
		}
		if err := res.AddVerified(l.Token, l.URI, l.Key, now); err != nil {
			return fmt.Errorf("verify: status list %d (%s): %w", i, l.URI, err)
		}
	}
	v.eng.StatusResolver = res
	return nil
}

// RevocationEnabled reports whether this verifier checks status-list revocation.
//
// It exists so a service can assert its own posture at startup and say so out
// loud. A verifier that silently does not check revocation looks identical to
// one that does, right up until a revoked token is accepted — and the operator
// finds out from the incident rather than from the log line.
func (v *Verifier) RevocationEnabled() bool { return v.eng.StatusResolver != nil }
