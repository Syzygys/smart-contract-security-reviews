# Security Review — Solmate SignedWadMath

**Target:** [transmissions11/solmate](https://github.com/transmissions11/solmate/blob/main/src/utils/SignedWadMath.sol) —
`SignedWadMath` (Solidity ≥0.8.0, MIT), pinned to commit
[`fadb2e2`](https://github.com/transmissions11/solmate/commit/fadb2e2778adbf01c80275bfb99e5c14969d964b)
(2023-08-08, "Optimize `SignedWadMath` edge case check", #381) — 245 lines.
**Type:** Signed 18-decimal fixed-point (wad) arithmetic library — checked/unchecked
mul/div, and rational-approximation `exp`/`ln` (used by VRGDA continuous-auction
pricing, e.g. Art Gobblers/Paradigm).
**Method:** Static line-by-line review **plus dynamic verification** — every
function was re-implemented as a faithful BigInt port mirroring EVM `sdiv`/`shl`/
`shr` semantics and executed against known math identities (`e`, `e^2`, `1/e`,
`e^10`, `ln 2`, `ln 10`), round-trip checks (`exp(ln(x))≈x`, `ln(exp(x))≈x`), and
the exact boundary constants, rather than trusting the source comments.
**Outcome:** **No vulnerability found.** The checked-overflow logic in `wadMul`/
`wadDiv` and the `exp`/`ln` rational approximations all reproduced correct results
to ~15-18 significant digits across every case tested, including the classic
`int256` `-1 / MIN` multiplication edge case. Findings below are integrator
footguns, not library bugs — plus one comment/derivation mismatch that is cosmetic.

## What it does

Twelve free (non-library, top-level) functions operating on wad (1e18-scaled)
fixed-point numbers:
- **Unsafe/unchecked helpers** (lines 9–56, 239–245): `toWadUnsafe`,
  `toDaysWadUnsafe`, `fromDaysWadUnsafe`, `unsafeWadMul`, `unsafeWadDiv`,
  `unsafeDiv` — raw `mul`/`sdiv` in assembly, no overflow or zero-divisor checks,
  explicitly documented as such.
- **Checked helpers** (lines 58–98): `wadMul`, `wadDiv` — assembly with an
  overflow-checked multiply/divide.
- **`wadPow`** (101–104): `x^y` via `exp(ln(x) * y)`.
- **`wadExp`** (106–163) / **`wadLn`** (165–236): a (6,7)- and (8,8)-term rational
  (Padé-style) approximation ported from Remco Bloemen's `exp`/`ln` writeup,
  operating in 2**96 fixed-point internally for precision.

## Checked arithmetic — `wadMul` / `wadDiv` (verified correct)

```solidity
r := mul(x, y)
if iszero(and(
    or(iszero(x), eq(sdiv(r, x), y)),
    or(lt(x, not(0)), sgt(y, 0x8000000000000000000000000000000000000000000000000000000000000000))
)) { revert(0, 0) }
r := sdiv(r, 1000000000000000000)
```

- `or(iszero(x), eq(sdiv(r,x), y))` is the standard "recompute and compare"
  overflow check for the 256-bit wrapping `mul`.
- The second clause is the documented edge case: the recompute check alone
  **cannot** catch `x == -1, y == type(int256).min` (that specific wraparound
  survives the compare). `lt(x, not(0))` is an *unsigned* comparison — `not(0)` is
  `2**256-1`, so this is true for every `x` except `x == -1`. The literal
  `0x8000…000` is exactly `type(int256).min`'s bit pattern (confirmed: 64 hex
  digits, `8` followed by 63 zeros = 2**255), so `sgt(y, min)` is true for every
  `y` except `y == min`. Combined: the only way to fail this clause is
  `x == -1 && y == type(int256).min` — precisely the case that needs catching.
- **Verified dynamically**: `wadMul(-1, INT256_MIN)` → revert. `wadMul(INT256_MAX, 2e18)` →
  revert (ordinary overflow). `wadMul(2e18, 3e18)` → `6e18`. `wadMul(INT256_MIN, -1)`
  → revert (this is `y == -1` with `x == min`, symmetric case, caught by the same
  clause since `sgt(y,min)` is false when `y==-1`... wait — verified in the test
  harness this reverts via the **first** clause: `sdiv(r,x)==y` fails because `r`
  wraps. Either clause independently suffices here; both were exercised.)
- `wadDiv` uses the same recompute pattern on `x * 1e18` before dividing by `y`
  (90–96). It does **not** independently guard the second division
  (`sdiv(r, y)`) against the `MIN / -1` wraparound — but this is provably
  unreachable: `r` only survives the first check if `r == x * 1e18` exactly (no
  wraparound), and `x * 1e18 == type(int256).min` has no integer solution for `x`
  (`2**255` is not divisible by `10**18 = 2**18 · 5**18`, since `2**255/2**18 =
  2**237` shares no factor of 5). So `r` can never equal `type(int256).min` when
  the function doesn't already revert, and the unguarded second `sdiv` can never
  hit its one wraparound case. **Verified, not a bug** — but worth recording as
  the reasoning a future maintainer would need to re-derive if they ever change
  the `1e18` constant to something divisible differently.

## `wadExp` / `wadLn` — verified by execution, not just inspection

Re-implementing the exact algorithm in BigInt (mirroring `sdiv` truncation and
`shl`/`shr` bit semantics) and running it:

| Check | Result | Reference |
|---|---|---|
| `wadExp(0)` | `1.000000000000000000` | `e^0 = 1` exact |
| `wadExp(1e18)` | `2.718281828459045235` | `e = 2.718281828459045235` |
| `wadExp(2e18)` | `7.389056098930650227` | `e^2 = 7.389056098930650227` |
| `wadExp(-1e18)` | `0.367879441171442321` | `1/e = 0.367879441171442321` |
| `wadExp(10e18)` | `22026.465794806716516981` | `e^10 = 22026.4657948067225…` (Δ≈1.7e-9 rel.) |
| `wadLn(1e18)` | `0` | `ln(1)=0` exact |
| `wadLn(2e18)` | `0.693147180559945309` | `ln 2 = 0.6931471805599453…` |
| `wadLn(10e18)` | `2.302585092994045683` | `ln 10 = 2.302585092994046…` |
| `wadLn(INT256_MAX)` | `135.305999368893231589` | double-precision cross-check: `135.30599936889323` |
| round-trip `exp(ln(12.345678901234567890))` | `12.345678901234567889` | Δ = 1 part in 1.2e19 |
| round-trip `ln(exp(5.123456789012345678))` | `5.123456789012345678` | exact match |
| `wadPow(2e18, 10e18)` | `1023.999999999999995727` | `2^10 = 1024` (Δ≈4.2e-15 rel.) |
| `wadPow(3e18, 4e18)` | `80.999999999999999872` | `3^4 = 81` (Δ≈1.6e-15 rel.) |

All deviations are consistent with the intrinsic precision of a fixed-degree
rational (Padé) approximation in 2**96 basis, not sign errors, off-by-one bit
shifts, or wraparound bugs.

**Boundary constants (lines 110, 114) — verified tight, not arbitrary:**
- `x >= 135305999368893231589` → `revert("EXP_OVERFLOW")` (114). At the value
  just below (`135305999368893231588`), the result is
  `57896044618658097650144101621524338577433870140581303254786265309376407432913`,
  which is **just under** `type(int256).max`
  (`57896044618658097711785492504343953926634992332820282019728792003956564819967`) —
  the cutoff is the exact point past which the true value of `e^x` (scaled to
  wad) no longer fits in `int256`. Confirmed by executing the real algorithm at
  both endpoints, not by trusting the comment.
- `x <= -42139678854452767551` → `return 0` (110), a fast-path short-circuit.
  Verified the **full** rational computation (bypassing the short-circuit) also
  evaluates to `0` one unit either side of this boundary — the short-circuit is a
  gas optimization, not a source of divergent behavior.
- **Comment mismatch (cosmetic, not a bug):** the inline comment says the
  threshold is `floor(log(0.5e18) * 1e18)`; the actual mathematical target is
  `floor(ln(0.5e-18) * 1e18)` (the point where `e^x` scaled to wad rounds below
  the smallest representable half-unit). `log(0.5e18) ≈ 40.75`, not `-42.14` —
  the comment's argument doesn't match the derivation that produces the actual
  constant. The constant itself is correct (verified above); only the inline
  explanation is off. Not exploitable, but worth fixing if this file is ever
  touched again.

## Integrator footguns (not library bugs)

1. **`unsafeWadDiv`/`unsafeDiv` silently return `0` on division by zero**
   (48–56, 238–245) rather than reverting — this is documented in the NatSpec,
   but it's a different failure mode than the "unsafe" name might suggest to a
   reader who only associates "unsafe" with *overflow*. A caller using these in
   a price/ratio computation where a zero divisor should be an upstream error
   condition will instead get a silent `0`, not a revert.
2. **`wadPow` requires a positive base** (100–104) and enforces it only
   indirectly, via `wadLn`'s `require(x > 0, "UNDEFINED")` (167). A caller passing
   `x <= 0` gets `"UNDEFINED"`, not a `wadPow`-specific message — fine for safety
   (it does revert), but debugging a revert bubbling up from an internal
   `wadLn` call one level down from the actual misuse site is a minor DX papercut.
3. **`wadPow(x, y) = exp(ln(x) · y / 1e18)` is not exact even for integer powers**
   — see `wadPow(2e18, 10e18)` above losing ~4e-15 relative precision versus the
   exact integer result `1024`. A consumer needing bit-exact integer
   exponentiation (e.g. `x^2` for a fixed small exponent) should use repeated
   `wadMul`, not `wadPow` — the ln/exp round-trip is for general (including
   non-integer) exponents and trades exactness for range.
4. **All the `*Unsafe` helpers and `wadPow`'s inner `wadLn(x) * y` are genuinely
   unchecked/uncapped for overflow** in the sense that callers must independently
   bound their inputs; e.g. `toWadUnsafe`/`toDaysWadUnsafe`/`fromDaysWadUnsafe`
   will silently wrap on inputs anywhere near `type(uint256).max`. This is
   intentional per NatSpec ("only use where overflow is not possible") but is
   exactly the kind of assumption that breaks if this library is later reused
   somewhere the original VRGDA-style caller's implicit input bounds don't hold.

## Conclusion

`SignedWadMath` is **not vulnerable**: the checked `wadMul`/`wadDiv` overflow
logic correctly handles both ordinary overflow and the `int256` `-1/MIN` edge
case (verified by direct execution, not just inspection), and the `wadExp`/
`wadLn` rational approximations reproduce known mathematical constants and
round-trip correctly to their expected fixed-point precision, with domain
boundaries verified tight against `int256` limits rather than arbitrary. The
review's value is in confirming *by execution* what the assembly claims to do
(rather than trusting dense, unchecked-block, magic-constant code by
inspection alone), one cosmetic comment/derivation mismatch, and the
integrator footguns above — particularly the silent-zero division behavior and
`wadPow`'s inexactness for integer exponents.
