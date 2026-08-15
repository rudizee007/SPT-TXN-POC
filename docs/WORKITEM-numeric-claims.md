# Work item — exact numeric claims (`UseNumber` migration)

**Status:** open, specified, not started.
**Class:** trust boundary. Spec first → implement → adversarial review in a
**fresh** context → property tests → human line-by-line. Not a refactor.
**Pinned by:** `internal/cttoken/numeric_precision_pin_test.go`. That test fails
the day this lands, by design. Deleting it is part of the work.

---

## 1. The defect

`cttoken.Verify` and `cattoken.Verify` decode claims with `json.Unmarshal` into
`map[string]any`. Every JSON number becomes `float64`, which is exact only to
2^53. Above that, a decoded ceiling is the nearest representable double.

Four consequences, escalating. The first was found by the pin test failing —
it was written expecting only imprecision.

**Above 2^53 the chain cannot carry a ceiling at all.** A CAT signed with
`9007199254740993` decodes to `9007199254740992`. A child requesting the
*byte-identical* value is then rejected for exceeding a ceiling its parent never
declared. Delegation of any ceiling in that range fails, and the error blames
the child for a widening it did not attempt:

```
attenuation rejected: scope dimension "max_amount":
value 9007199254740993 exceeds parent ceiling 9007199254740992
```

Fail-closed, therefore safe. Also unusable, and the diagnostic names the wrong
party — which is the shape of message that costs an afternoon before anyone
suspects the decoder. Measured, not assumed: float64 spacing at 10^18 is **128**,
so every wei-scale ceiling is quantised to a multiple of 128.



**The comparison is asymmetric.** `tbac.TxnScope` deliberately carries the
transaction amount as `json.Number` — its own comment says "the exact decimal
string ... not lossy float64 — important for large values like XRP drops
(> 2^53)". So an exact transaction amount is compared against a rounded ceiling.
One side of the authorization decision was hardened and the other was not.

**Rounding is not always downward.** Downward is conservative — the verifier
enforces slightly less than was granted. Upward enforces *more*. Measured across
a 129-value band around 10^18: **64 of 129 ceilings decode higher than signed**,
by up to 64 wei. Authority widened by float representation rather than by any
delegation step, which is the one thing the attenuation model exists to make
impossible.

**The ZK chain proof inherits it.** `verifier/engine.go` passes
`uint64(maxAmt)` — derived from that `float64` — as a public input to
`ChainVerifier`. The proof can be bound to a ceiling that is not the ceiling in
the token.

Nothing has surfaced because USD cents do not reach 2^53. Wei and drops do,
routinely, and the OT profile's engineering units will have their own ranges.

---

## 2. Why it was not fixed in place

`json.Decoder.UseNumber()` is a one-line change that flips the dynamic type of
every numeric claim simultaneously. **16 non-test call sites** assert
`.(float64)` today:

| Package | Sites | Trust boundary |
|---|---|---|
| `internal/cttoken` | 5 | yes |
| `internal/verifier` | 4 | yes |
| `internal/txntoken` | 2 | yes |
| `internal/cattoken` | 1 | yes |
| `internal/decision` | 1 | yes |
| `internal/statuslist` | 1 | no |
| `internal/sdjwt` | 1 | no |
| `cmd/catsvc` | 1 | no |

Every one of those assertions becomes `false` on the same commit. Each site then
takes whichever branch it has for "absent or wrong type", and those branches are
not uniform — some return an error, some skip a block. Sixteen simultaneous
behaviour changes in the authorization path, where the failure mode of getting
one wrong is a check that silently stops running.

`txntoken.go:169` shows the hazard shape even though it is currently correct:

```go
if parentExpF, ok := parent["exp"].(float64); ok {
    ... enforce child exp <= parent exp ...
} else {
    return nil, fmt.Errorf("parent CT missing exp")
}
```

It fails closed *because someone wrote the `else`*. A site with the same shape
and no `else` would silently stop enforcing its constraint, and the suite would
stay green because no test asserts "this check ran".

---

## 3. Required order

Each step ships and is reviewed on its own. Steps 1–3 are behaviour-preserving;
only step 4 changes anything observable.

1. **Shared accessor.** One package (`internal/claims`) exposing exact readers
   that accept `float64`, `json.Number`, and Go integer types:
   `Int64(m, name) (int64, bool)` and `Rat(m, name) (*big.Rat, bool)`.
   `verifier.intClaim` is the existing seam and its `int64`-not-`int` rationale
   (32-bit truncation making a negative parent `exp` compare as attenuation)
   must be carried over verbatim, not re-derived.

2. **Migrate all 16 sites** to the accessors, decoder unchanged. Behaviour is
   identical because the accessors still accept `float64`. This is the step that
   makes the flip safe, and it is reviewable site by site.

3. **Assert the denominator.** A test that enumerates the numeric claims each
   verification step reads and asserts each is read through an accessor — so a
   future `.(float64)` reintroduction fails rather than merely regressing.
   Without this, step 2 is a one-time cleanup that decays.

4. **Flip the decoders** to `UseNumber()` in `cttoken`, `cattoken` and any other
   claim decode path. Delete the pin test. Add the round-trip test it was
   standing in for: a ceiling of 2^53+1 and one of 10^18−1 survive
   issue → verify → compare exactly.

5. **`uint64(maxAmt)` in `engine.go`** becomes an exact conversion with an
   explicit range check. A ceiling that does not fit `uint64` must fail closed,
   not truncate — that is the same narrowing hazard as the Cardano
   `uint64`→`uint` cast, and it sits on the ZK public input.

6. **Mutation-verify.** For each accessor: make it silently return the zero
   value instead of `false` on a type it does not recognise, and confirm the
   suite fails. An accessor that cannot be observed failing is not a guard.

---

## 4. Scope boundary

This work item covers **exactness of numeric claims only**.

It does **not** implement two-sided value constraints, floors, bands, interval
attenuation, escalation budgets or cumulative counters. Those are gated
separately and are not unblocked by this. The adjacent change already made —
requiring numeric *direction* to be declared (`tbac.numericDirection`) — is
about which way narrowing runs; this one is about whether the number survives
being read. They are independent, and neither completes the other.
