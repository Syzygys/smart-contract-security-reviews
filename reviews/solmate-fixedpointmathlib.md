# Security Review — Solmate FixedPointMathLib

**Target:** [transmissions11/solmate](https://github.com/transmissions11/solmate/blob/f2833c7cc951c50e0b5fd7e505571fddc10c8f77/src/utils/FixedPointMathLib.sol) — `FixedPointMathLib` (Solidity ≥0.8.0, AGPL-3.0), pinned at commit `f2833c7c` ("⚡️ Memory safe assembly", 2022-10-27, last commit to touch this file; verified byte-identical to current `main` at review time)
**Type:** Gas-optimized fixed-point (WAD) arithmetic library — `mulWad`/`divWad`, low-level `mulDiv`, integer `rpow` (compounding exponentiation), integer `sqrt`, and three explicitly-"unsafe" div/mod helpers. Pure functions, no state, no external calls.
**Method:** Static, line-by-line review of the pinned raw source (255 lines — the entire file), including manual re-derivation of the assembly overflow-check identities and a manual trace of the `rpow` exponentiation-by-squaring loop against the textbook algorithm it implements.
**Outcome:** **No vulnerability found.** Every overflow guard in the assembly was re-derived by hand and holds; the `sqrt` implementation was traced through the `x = 0` edge case (EVM's div/mod-by-zero-returns-0 semantics, not a revert) and confirmed correct. One **comment/code mismatch** was found in `rpow` (misleading, not exploitable — documented below). The real risk for integrators is not a bug in this file but a genuine behavioral gap versus OpenZeppelin's `Math.mulDiv`, detailed below.

## What it does

A `library` of `internal` `pure` functions meant to be used via `using FixedPointMathLib for uint256`, not deployed standalone. Three tiers: (1) WAD-scaled convenience wrappers `mulWadDown/Up`, `divWadDown/Up` (lines 16–30); (2) the low-level primitives they're built on, `mulDivDown`, `mulDivUp`, `rpow` (lines 36–158); (3) general-purpose `sqrt` and three `unsafe*` div/mod helpers that trade reverting for returning `0` (lines 164–255). All arithmetic is done in `assembly`, so none of Solidity 0.8's automatic checked-arithmetic reverts apply — every overflow guard visible in this file is a guard the authors wrote by hand, not a compiler safety net.

## `mulDivDown` / `mulDivUp` — overflow check re-derived, correct

```solidity
function mulDivDown(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 z) {
    assembly {
        // Equivalent to require(denominator != 0 && (y == 0 || x <= type(uint256).max / y))
        if iszero(mul(denominator, iszero(mul(y, gt(x, div(MAX_UINT256, y)))))) {
            revert(0, 0)
        }
        z := div(mul(x, y), denominator)
    }
}
```

The comment claims an equivalence to a readable `require`. Re-deriving it rather than trusting the comment:

- **`y == 0` case:** `div(MAX_UINT256, 0)` is `0` under EVM semantics (division by zero yields `0`, it does not trap). So `gt(x, 0)` is `1` unless `x == 0`, but it's multiplied by `y = 0` regardless (`mul(y, ...)`), giving `0`. `iszero(0) = 1`. The whole expression collapses to `iszero(mul(denominator, 1))` = `iszero(denominator)` — i.e. the check degenerates to exactly "revert if `denominator == 0`", correctly matching the `y == 0 ⟹ x*y` can never overflow, so no overflow check is needed for that branch.
- **`y != 0` case:** `gt(x, div(MAX_UINT256, y))` is the standard `x > type(uint256).max / y` overflow predicate for `x * y` (integer-division truncation makes this predicate exact, not approximate, for this specific comparison — a well-known identity, not new to this review). When it's `1` (overflow), `mul(y, 1) = y ≠ 0`, so `iszero(y) = 0`, so `mul(denominator, 0) = 0`, so `iszero(0) = 1` → **revert**. When it's `0` (no overflow), the expression reduces to `iszero(denominator)` → revert only if `denominator == 0`, otherwise fall through.

Both branches match the stated `require` exactly. ✔ `mulDivUp` (lines 53–69) reuses the identical guard and only differs in the final rounding (`add(gt(mod(mul(x,y), denominator), 0), div(mul(x,y), denominator))` — adds 1 iff there's a nonzero remainder), which is the standard round-up-division identity. ✔

**Verdict: correct overflow guard on both functions, re-derived rather than assumed.**

## `rpow` — exponentiation-by-squaring re-derived; one comment bug (non-exploitable)

```solidity
function rpow(uint256 x, uint256 n, uint256 scalar) internal pure returns (uint256 z) {
    assembly {
        switch x
        case 0 { switch n case 0 { z := scalar } default { z := 0 } }
        default {
            switch mod(n, 2) case 0 { z := scalar } default { z := x }
            let half := shr(1, scalar)
            for { n := shr(1, n) } n { n := shr(1, n) } {
                if shr(128, x) { revert(0, 0) }
                let xx := mul(x, x)
                let xxRound := add(xx, half)
                if lt(xxRound, xx) { revert(0, 0) }
                x := div(xxRound, scalar)
                if mod(n, 2) {                      // <- comment above this line says "If n is even:"
                    let zx := mul(z, x)
                    if iszero(eq(div(zx, x), z)) { if iszero(iszero(x)) { revert(0, 0) } }
                    let zxRound := add(zx, half)
                    if lt(zxRound, zx) { revert(0, 0) }
                    z := div(zxRound, scalar)
                }
            }
        }
    }
}
```

This computes `(x/scalar)^n * scalar` (fixed-point compounding, e.g. for interest-rate accrual), via the standard textbook loop:
```
z = (n is odd) ? x : scalar
for (n >>= 1; n != 0; n >>= 1) {
    x = round(x*x / scalar)
    if (n is odd) z = round(z*x / scalar)
}
```
Mapping the assembly to this line by line: the initial `switch mod(n, 2)` seeds `z = x` when the *original* `n` is odd — matches. The loop's `if mod(n, 2)` (line 132 of the source) tests the *already-halved* `n`, i.e. whether the **current** bit being processed is set — that only happens when `n` (after the shift) is **odd**, not even. **The comment directly above it, `// If n is even:`, is backwards** — the branch actually fires on odd bits, which is what the algorithm requires (skip the `z` update on a 0-bit, apply it on a 1-bit). Traced against the reference algorithm above, the *code* is correct; only the inline comment is mislabeled. This has no security consequence — it cannot be exploited, it can only mislead a future maintainer reading the assembly without re-deriving it from scratch, which is exactly the trap this review avoided by re-deriving it. Confirmed present in the pinned commit (not a transcription artifact of this review) — verify at [line 131 of the pinned source](https://github.com/transmissions11/solmate/blob/f2833c7cc951c50e0b5fd7e505571fddc10c8f77/src/utils/FixedPointMathLib.sol#L131).

Overflow guards, checked individually:
- `if shr(128, x) { revert(0, 0) }` (line 113) — reverts if `x ≥ 2^128` *before* squaring. Assembly `mul` wraps silently on overflow (no automatic revert), so this is the guard that makes `mul(x, x)` safe: if `x < 2^128` then `x*x < 2^256`, no wraparound possible. ✔
- `if lt(xxRound, xx) { revert(0, 0) }` (line 124) — `add` also wraps silently; this detects overflow in `xx + half` by checking the sum didn't decrease. ✔ Same pattern reused for `zxRound`/`zx`. ✔
- The `z*x` overflow check (`iszero(eq(div(zx, x), z))`) has a deliberate `x == 0` carve-out: when `x == 0`, `div(zx, x) = div(0, 0) = 0` under EVM's div-by-zero-returns-0 rule, which would make `eq(0, z)` spuriously false whenever `z ≠ 0` and wrongly look like an overflow — the nested `if iszero(iszero(x))` (i.e. "only revert if `x` is actually nonzero") suppresses that false positive. Traced through both the `x == 0` and `x != 0` sub-cases explicitly; both resolve correctly. ✔

**Verdict: the arithmetic and control flow are correct; one inline comment is inverted (cosmetic, not a vulnerability).**

## `sqrt` — Babylonian method, `x = 0` edge case traced, correct

The initial-estimate ladder (lines 176–191) and 7 Newton-Raphson iterations (lines 212–218) are the well-known Solmate/Uniswap-V2-derived integer sqrt, already battle-tested across the ecosystem. The one edge case worth tracing explicitly rather than assuming "it's famous, it's fine": **`x = 0`**. All four `if iszero(lt(y, ...))` branches are false (since `y = x = 0` is less than every threshold), so `z` stays at its literal initial value `181`. Then `z := shr(18, mul(z, add(y, 65536)))` = `shr(18, 181 * 65536)` = `45`. The Newton-Raphson loop repeatedly computes `div(x, z)` with `x = 0`, i.e. `div(0, z) = 0` (ordinary, not a div-by-zero case since `z` is nonzero at every step until it collapses to `0` after enough halvings, at which point `div(0, 0) = 0` under EVM's zero-division rule rather than a trap). Manually iterating: `45 → 22 → 11 → 5 → 2 → 1 → 0 → 0`, and the final correction `z := sub(z, lt(div(x, z), z))` evaluates `lt(div(0, 0), 0) = lt(0, 0) = 0`, leaving `z = 0`. **`sqrt(0) = 0`, correctly, with no revert anywhere in the path** — despite the function dividing by a value (`z`) that does reach `0` partway through the iteration. ✔

## `unsafeMod` / `unsafeDiv` / `unsafeDivUp` — behave exactly as named

Thin `assembly` wrappers around `mod`/`div` that return `0` on a zero divisor instead of reverting (EVM native behavior — Solidity's checked division normally reverts on `y == 0`; these functions deliberately bypass that by dropping to assembly). Correctly named and documented as "unsafe" in the source comments; the only reason to flag them here is the integrator footgun below, not a defect in the functions themselves. ✔

## Integrator footgun: `mulDiv*` reverts on "phantom overflow" the true result wouldn't have

`mulDivDown`/`mulDivUp` require `x * y` itself to fit in `uint256` — they revert whenever the *intermediate product* overflows, even if the final `(x*y)/denominator` would have fit comfortably. This is a real, documented design tradeoff versus OpenZeppelin's `Math.mulDiv`, which uses full 512-bit intermediate arithmetic (via the `mulmod`/two-word decomposition technique) and only fails when the *final result* doesn't fit. Concretely: `mulDivDown(2^200, 2^200, 2^200)` — a case where the true answer is exactly `2^200`, well within range — reverts here because `2^200 * 2^200` overflows `uint256` before the division happens, whereas OZ's version returns `2^200` successfully. Solmate's own WAD wrappers (`mulWadDown` etc.) are safe in the overwhelmingly common case of token-amount-times-price-ratio at 1e18 scale, but any integrator composing `mulDivDown` directly with two large, independently-scaled `uint256` values (e.g. multiplying two already-large intermediate results before a final division) should be aware this can revert on inputs that are mathematically valid. This is not a bug — it's a documented gas/precision tradeoff of the "simplified" mulDiv approach — but it is the single most consequential difference from OZ's `Math.mulDiv` for anyone porting code between the two libraries.

## Integrator footgun: `revert(0, 0)` everywhere — no error selector, no reason string

Every guard in this file reverts with empty returndata (`revert(0, 0)`), consistent with Solmate's gas-optimized style throughout the codebase (already noted for `SafeTransferLib` and `Address`-equivalent reviews in this portfolio). A caller wrapping these functions in `try/catch` gets no distinguishing reason between "denominator was zero," "overflow," or "assembly guard tripped" — all look identical. Front-end/bot integrations that parse revert reasons for user-facing error messages need their own pre-flight checks; they cannot rely on this library's revert data to tell them what went wrong.

## Integrator footgun: `rpow`'s `scalar` is caller-trusted, not validated against `x`

`rpow(x, n, scalar)` has no relationship check between `x`'s implicit fixed-point base and the `scalar` argument — passing a `scalar` that doesn't match how `x` was actually scaled (e.g. calling with `scalar = 1e18` on a `x` that's really USDC-scaled at `1e6`) produces a silently wrong but syntactically valid `uint256`; there is no revert to signal the mismatch. This is unavoidable for a generic library function (it has no way to know the caller's intended scale) but is worth stating explicitly as a caller obligation, not something the library defends against.

## Conclusion

`FixedPointMathLib` is **not vulnerable**: the `mulDivDown`/`mulDivUp` overflow guard was re-derived from the raw assembly (not taken on the comment's word) and holds in both the `y == 0` and `y != 0` branches; `rpow`'s exponentiation-by-squaring loop and every one of its four hand-written overflow checks were traced against the textbook algorithm and are correct, modulo one **inverted inline comment** (`"If n is even:"` guarding a branch that actually fires on odd bits) that is misleading but not exploitable; and `sqrt`'s `x = 0` path was walked through explicitly to confirm it terminates at `0` without hitting a division trap, relying on EVM's div-by-zero-returns-0 semantics rather than assuming the well-known algorithm "just works" at the boundary. The actionable output for an integrator is the gap between this library's `mulDiv` (reverts on intermediate-product overflow) and OpenZeppelin's `Math.mulDiv` (only reverts on final-result overflow, via full 512-bit arithmetic) — a real behavioral difference to account for when porting code or composing this library with large, independently-scaled values, not a defect in either implementation.
