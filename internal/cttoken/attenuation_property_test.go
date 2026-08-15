package cttoken_test

// Property-based test for delegation attenuation — per docs/THREAT-MODEL.md
// §4.2 this is the single highest-value test in the codebase: generate random
// delegation chains and assert authority NEVER widens at any hop, under any
// input. Legitimate narrowings must chain and verify; attempted widenings
// must be rejected at construction, at every depth, every time.

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
)

var currencies = []string{"USD", "EUR", "GBP", "JPY"}
var actionsPool = []string{"transfer", "quote", "read", "refund", "hold"}

// randRootScope builds a random but well-formed root capability scope.
func randRootScope(rng *rand.Rand) cattoken.CapabilityScope {
	scope := cattoken.CapabilityScope{
		"max_amount": rng.Intn(1_000_000) + 1000,
		"currency":   currencies[rng.Intn(len(currencies))],
	}
	// Random list dimension.
	n := rng.Intn(len(actionsPool)) + 1
	acts := make([]any, 0, n)
	for _, a := range actionsPool[:n] {
		acts = append(acts, a)
	}
	scope["actions"] = acts
	if rng.Intn(2) == 0 {
		scope["region"] = map[string]any{"zone": fmt.Sprintf("z%d", rng.Intn(4)), "tier": rng.Intn(5) + 1}
	}
	return scope
}

// narrow produces a legitimately attenuated child of parent.
//
// NOTE ON THE NUMERIC CASES. Generating a value <= parent is "narrowing" only
// because every numeric dimension this generator produces is a declared CEILING
// (tbac.numericDirection). It is not a general truth about numbers, and this
// generator previously encoded it as one: it applied `rng.Intn(tv+1)` to any
// numeric dimension whatever, so a floor — a minimum acceptable output, the
// shape a swap needs — would have been generated smaller and asserted valid.
// The property test would then have certified the sandwich bypass as correct
// attenuation, which is worse than not testing it, because a passing property
// test is read as proof.
//
// If you add a numeric dimension to randRootScope, it must be a declared
// ceiling. tbac.TestUndeclaredNumericDimensionIsRefused holds the other half:
// anything undeclared is rejected rather than assumed.
func narrow(rng *rand.Rand, parent tbac.Scope) tbac.Scope {
	child := tbac.Scope{}
	for dim, v := range parent {
		// Randomly drop a dimension entirely (dropping is narrowing).
		if rng.Intn(4) == 0 && dim != "max_amount" {
			continue
		}
		switch tv := v.(type) {
		case int:
			child[dim] = rng.Intn(tv + 1) // 0..parent (<= ceiling)
		case float64:
			child[dim] = float64(rng.Intn(int(tv) + 1))
		case string:
			child[dim] = tv // strings must match exactly
		case []any:
			// Random non-empty subset (prefix suffices for subset semantics).
			k := rng.Intn(len(tv)) + 1
			sub := make([]any, k)
			copy(sub, tv[:k])
			child[dim] = sub
		case map[string]any:
			child[dim] = map[string]any(narrow(rng, tbac.Scope(tv)))
		default:
			child[dim] = tv
		}
	}
	return child
}

// widen produces a child that exceeds parent in exactly one random way.
func widen(rng *rand.Rand, parent tbac.Scope) tbac.Scope {
	child := narrow(rng, parent)
	switch rng.Intn(4) {
	case 0: // numeric ceiling exceeded
		if v, ok := parent["max_amount"].(int); ok {
			child["max_amount"] = v + 1 + rng.Intn(1000)
		} else {
			child["max_amount"] = 1 << 40
		}
	case 1: // dimension the parent never held
		child[fmt.Sprintf("new_dim_%d", rng.Intn(1000))] = "surprise"
	case 2: // string mutation
		if cur, ok := parent["currency"].(string); ok {
			for _, c := range currencies {
				if c != cur {
					child["currency"] = c
					break
				}
			}
		} else {
			child["currency"] = "XXX"
		}
	default: // list superset
		if acts, ok := parent["actions"].([]any); ok {
			child["actions"] = append(append([]any{}, acts...), "escalate")
		} else {
			child["actions"] = []any{"escalate"}
		}
	}
	return child
}

func TestProperty_AttenuationNeverWidens(t *testing.T) {
	const trials = 200
	for seed := int64(0); seed < trials; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			issuerPub, issuerPriv := keypair(t)
			holder, _ := keypair(t)

			depth := rng.Intn(5) + 2 // 2..6 hops allowed
			rootScope := randRootScope(rng)
			cat := issueParentCAT(t, issuerPriv, holder, rootScope, depth)

			// Hop 0: CAT -> CT.
			parentScope := tbac.Scope(rootScope)
			ct, err := cttoken.Issue(cttoken.IssueRequest{
				Issuer:          "domain-a.authorg",
				ParentCAT:       cat.Token,
				ParentIssuerKey: issuerPub,
				RequestedScope:  narrow(rng, parentScope),
				HolderPublicKey: holder,
				TTL:             time.Minute * 5,
			}, issuerPriv)
			if err != nil {
				t.Fatalf("root CT issuance of narrowed scope failed: %v", err)
			}

			// Walk random hops until depth exhausts.
			parent := ct
			for hop := 0; ; hop++ {
				parentClaims := parent.Claims
				parentScope := tbac.Scope(parentClaims["capability_scope"].(map[string]any))
				remaining := asInt(t, parentClaims["delegation_depth_remaining"])

				attack := rng.Intn(2) == 0
				var requested tbac.Scope
				if attack {
					requested = widen(rng, parentScope)
				} else {
					requested = narrow(rng, parentScope)
				}

				subHolder, _ := keypair(t)
				// TTL must decay: give each hop half the parent's remaining
				// life (never zero — zero means DefaultTTL).
				hopTTL := time.Until(parent.ExpiresAt) / 2
				if hopTTL < 2*time.Second {
					hopTTL = 2 * time.Second // will be rejected if it overruns the parent — also a valid outcome to exercise
				}
				child, err := cttoken.Delegate(cttoken.DelegateRequest{
					Issuer:          "domain-a.authorg",
					ParentCT:        parent.Token,
					ParentIssuerKey: issuerPub,
					RequestedScope:  requested,
					HolderPublicKey: subHolder,
					TTL:             hopTTL,
				}, issuerPriv)

				if attack {
					if err == nil {
						// The single forbidden outcome: verify the widened
						// grant really escaped containment before failing.
						childScope := tbac.Scope(child.Claims["capability_scope"].(map[string]any))
						if cErr := tbac.Contains(parentScope, childScope); cErr != nil {
							t.Fatalf("hop %d: WIDENING ACCEPTED: parent=%v child=%v (%v)", hop, parentScope, childScope, cErr)
						}
						// Requested a widen but got a contained scope — the
						// issuer must never silently rewrite a request.
						t.Fatalf("hop %d: widening request silently accepted with scope %v", hop, child.Claims["capability_scope"])
					}
					continue // rejected as required; try another mutation at same parent
				}

				if remaining <= 0 {
					if err == nil {
						t.Fatalf("hop %d: delegation beyond depth bound accepted", hop)
					}
					break // depth exhausted and enforced — chain ends
				}
				if err != nil {
					t.Fatalf("hop %d: legitimate narrowing rejected: %v (parent=%v requested=%v)", hop, err, parentScope, requested)
				}

				// Invariants on the accepted child.
				childScope := tbac.Scope(child.Claims["capability_scope"].(map[string]any))
				if cErr := tbac.Contains(parentScope, childScope); cErr != nil {
					t.Fatalf("hop %d: accepted child not contained in parent: %v", hop, cErr)
				}
				if got := asInt(t, child.Claims["delegation_depth_remaining"]); got != remaining-1 {
					t.Fatalf("hop %d: depth %d, want %d", hop, got, remaining-1)
				}
				if child.ExpiresAt.After(parent.ExpiresAt) {
					t.Fatalf("hop %d: child TTL exceeds parent (child %v > parent %v)", hop, child.ExpiresAt, parent.ExpiresAt)
				}
				if child.HumanAnchor != parent.HumanAnchor {
					t.Fatalf("hop %d: humanAnchor mutated", hop)
				}
				parent = child
			}
		})
	}
}

func asInt(t *testing.T, v any) int {
	t.Helper()
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	default:
		t.Fatalf("depth claim has type %T", v)
		return 0
	}
}
