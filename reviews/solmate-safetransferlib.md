# Security Review — Solmate SafeTransferLib

**Target:** [transmissions11/solmate](https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol) — `SafeTransferLib` (Solidity ≥0.8.0, AGPL-3.0)
**Type:** ETH / ERC-20 transfer wrapper that tolerates non-standard return values
**Method:** Static, line-by-line review of the pinned raw source (124 lines)
**Outcome:** **No vulnerability in the library.** Its success-determination logic is
correct; the real risks are documented footguns that *integrators* must respect —
enumerated below so a reviewer doesn't miss them.

## What it does

Four internal functions — `safeTransferETH`, `safeTransferFrom`, `safeTransfer`,
`safeApprove` — each perform a low-level `call` in assembly and derive a `success`
boolean that tolerates the three real-world token behaviours: (a) returns a proper
`true`, (b) returns nothing but has code (e.g. USDT), (c) reverts.

## The success-check logic (the interesting part) — correct

For the ERC-20 functions the derivation is (identical across all three):

```solidity
success := call(gas(), token, 0, ptr, len, 0, 32)
if and(iszero(and(eq(mload(0), 1), gt(returndatasize(), 31))), success) {
    success := iszero(or(iszero(extcodesize(token)), returndatasize()))
}
```

Decoded:
- **Reverted** → `call` yields `success = 0` → reverts on the outer `require`. ✔
- **Returned a clean 32-byte `1`** (`mload(0)==1 && returndatasize>31`) → the `if`
  does not fire → `success` stays true. ✔
- **Succeeded but not a clean `true`** → the `if` fires and recomputes:
  `success = (extcodesize(token) != 0) AND (returndatasize == 0)`. So it accepts
  **only** the "has code + returned nothing" case (USDT-style), and rejects an
  explicit `false` or non-`1` data. ✔
- **No-code address** (EOA / never-deployed / self-destructed token): `call`
  succeeds with no return data, so the `if` fires; `extcodesize == 0` makes
  `success = false` → **reverts.** The classic "silent success when transferring to
  a non-contract" does **not** apply to this version. ✔

The `gt(returndatasize(), 31)` guard is what makes reading the possibly-dirty
`mload(0)` scratch slot safe: a short/empty return can never be mistaken for `1`.

**Verdict: the return-value handling is correct across the token taxonomy.**

## Real caveats an integrator must respect (not library bugs — documented footguns)

A review is only useful if it names where *misuse* bites:

1. **`safeApprove` is not "safe" against the approval footgun.** It only wraps
   return-value handling. It does **not** address the ERC-20 approve race, nor the
   "must set allowance to 0 before changing" requirement of tokens like USDT. A
   caller expecting `safeApprove` to be safe against allowance-change issues is
   wrong; that remains the integrator's responsibility.
2. **All gas is forwarded** (`gas()`). SafeTransferLib is **not** a reentrancy
   guard — a malicious/hookful token (ERC-777-style) can reenter or grief gas. The
   caller must apply checks-effects-interactions / a guard.
3. **Token-existence is only asserted inside the no-return-data branch.** Correct by
   design, but it means a caller must not assume the library validates
   "token-ness" for any other purpose. If a token returns a proper `true`, its code
   size is never checked at all (it doesn't need to be — a clean `true` implies code
   executed).
4. **Deliberate memory dirtiness.** The library's own NatSpec warns it "knowingly
   create[s] dirty bits at the destination of the free memory pointer." Callers
   doing their own adjacent inline assembly must account for this.

## Conclusion

`SafeTransferLib` is **not vulnerable**: its clever assembly correctly distinguishes
success from failure across standard, missing-return, and reverting tokens, and
reverts on non-contract targets. The genuine review value is in the **integration
caveats** — especially that `safeApprove`'s name overpromises, and that the library
provides no reentrancy protection. These are the points that turn a "looks fine"
skim into a review an integrator can actually act on.
