# Security Review — OpenZeppelin SafeERC20

**Target:** [OpenZeppelin/openzeppelin-contracts @ v5.6.1](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/token/ERC20/utils/SafeERC20.sol) — `SafeERC20` (280 lines, last updated v5.5.0, MIT)
**Type:** ERC-20 interaction wrapper tolerating non-standard tokens
**Method:** Static, line-by-line review of the real source
**Outcome:** **No vulnerability found.** The return-value taxonomy is handled
correctly and `forceApprove` implements the approve-race dance properly. The real
content is the allowance-race semantics an integrator must understand.

## Token taxonomy handling — correct

`safeTransfer`/`safeTransferFrom` (L33-45) route through `_safeTransfer(...)`, which
accepts the three real token behaviours: returns `true`, returns nothing (assumed
success on a non-reverting call), or reverts. A `false` return or a revert becomes
`SafeERC20FailedOperation(token)`. `try*` variants (L52-60) return a bool instead of
reverting. Same intent as Solmate's `SafeTransferLib`
([solmate-safetransferlib.md](solmate-safetransferlib.md)), different implementation
(Solidity-level `_callOptionalReturn` rather than raw assembly).

## `forceApprove` — the approve-race, handled

```solidity
function forceApprove(IERC20 token, address spender, uint256 value) internal {
    if (!_safeApprove(token, spender, value, false)) {   // try direct approve
        _safeApprove(token, spender, 0, true);            // fall back: set to 0 …
        _safeApprove(token, spender, value, true);        // … then to value
    }
}
```
Tokens like USDT revert on `approve(spender, X)` when the current allowance is
non-zero (they require `approve(0)` first). `forceApprove` tries the direct approve,
and only on failure performs the zero-then-value sequence. Correct handling of the
best-known non-standard-approval footgun. `safeIncreaseAllowance` /
`safeDecreaseAllowance` (L72-92) read the current allowance and `forceApprove` to the
new total; `safeDecreaseAllowance` reverts `SafeERC20FailedDecreaseAllowance` if the
requested decrease exceeds the current allowance (no underflow, clear error).

**Verdict: transfer and approve paths are correct across the token taxonomy.**

## Real caveats an integrator must respect

1. **`safeApprove` was removed; `forceApprove` ≠ front-running protection.** The
   ERC-20 approve *race* (a spender front-running an allowance change to spend the
   old + new amount) is a **protocol-design** problem. `forceApprove` only handles
   the *token-implementation* quirk (must-zero-first); it does not eliminate the
   approve race. Prefer allowance patterns that don't leave a standing approval, or
   use `safeIncrease/DecreaseAllowance` with awareness of the same race.
2. **`safeIncreaseAllowance`/`safeDecreaseAllowance` are read-then-write.** They
   read `allowance(...)` and write `old ± delta`. Within one transaction this is
   fine; do not assume atomicity against a concurrent allowance change across
   transactions.
3. **ERC-7674 temporary allowance is not touched by `forceApprove`** (L101 NOTE):
   if a token implements transient allowances, `forceApprove` modifies only the
   persistent allowance. Integrators mixing the two must account for it.
4. **"Returns nothing = success" assumes the address has code.** As with any
   optional-return wrapper, calling these against a non-contract can misbehave;
   ensure `token` is a real deployed ERC-20 (SafeERC20's `_callOptionalReturn`
   guards this, but the caller should not pass unvetted addresses).

## Conclusion

`SafeERC20` is **not vulnerable**: it correctly normalises non-standard return
values and `forceApprove` implements the zero-then-value approval dance. The
actionable guidance is that it solves *token non-conformance*, not the *approve
race* — that remains a protocol-level design responsibility for the integrator.
