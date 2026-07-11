# Security Review — OpenZeppelin ReentrancyGuard

**Target:** [OpenZeppelin/openzeppelin-contracts @ v5.6.1](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/ReentrancyGuard.sol) — `ReentrancyGuard` (119 lines, MIT)
**Type:** Reentrancy-protection base contract (`nonReentrant` modifier)
**Method:** Static, line-by-line review of the real source
**Outcome:** **No vulnerability found.** The lock is correct and uses the standard
non-zero sentinel + namespaced storage. The important content is what the guard
does **not** protect against — cross-contract and read-only reentrancy — which is
the caller's responsibility.

## The lock — correct

State is a `uint256` at an ERC-7201 namespaced slot (`REENTRANCY_GUARD_STORAGE`,
L36), with `NOT_ENTERED = 1`, `ENTERED = 2` (L50-51). The modifier:

```solidity
modifier nonReentrant() { _nonReentrantBefore(); _; _nonReentrantAfter(); }
```
- `_nonReentrantBefore` (L94-100): reverts `ReentrancyGuardReentrantCall` if status
  is already `ENTERED`, else sets `ENTERED`.
- `_nonReentrantAfter` (L102-105): restores `NOT_ENTERED`.

Two deliberate design choices, both correct:
1. **`1`/`2` instead of `0`/`1`.** Keeping the "unlocked" value non-zero avoids the
   expensive zero→non-zero `SSTORE` on every guarded call, and the reset to
   `NOT_ENTERED` (L104 comment cites EIP-2200) triggers the gas refund. Not a
   security property, but the reason the sentinel is not `0`.
2. **ERC-7201 namespaced storage slot.** Placing the flag at a derived slot (not a
   plain state variable) avoids storage-layout collisions in upgradeable/diamond
   compositions — a real hardening over the naive `uint256 private _status`.

`nonReentrantView` (L83-86) is a view-only variant that *checks* the flag without
changing it — for view functions that must not be callable mid-`nonReentrant`
(read-only reentrancy mitigation, but see caveat 2).

**Verdict: the mutex is correct; entry during an active guard reverts.**

## Real caveats (where reentrancy still bites)

1. **Same-contract nesting is blocked — by design, but a footgun.** Calling one
   `nonReentrant` function from another *in the same contract* reverts. The NatSpec
   (L64-67) prescribes the fix: make the outer function `external nonReentrant` and
   have it call a `private` worker that holds the real logic. Refactors that add a
   second `nonReentrant` entry to an internal path will brick legitimate flows.
2. **It does NOT stop cross-contract or read-only reentrancy.** The guard is
   per-contract state. If contract A (guarded) calls out to B, and B calls back into
   a *different, unguarded* contract C that reads A's now-inconsistent state, A's
   guard never fires. Read-only reentrancy (the class behind several real DeFi
   exploits) attacks exactly the window where A's state is mid-update but a *view*
   is queried — `nonReentrantView` only helps if you actually apply it to those
   views. This library gives you a mutex; a correct checks-effects-interactions
   ordering is still mandatory.
3. **Guard held across the whole function.** The flag is set for the entire body,
   so an external call anywhere inside a `nonReentrant` function cannot re-enter
   *that* contract — but it also means composing guarded contracts that legitimately
   call each other needs care (caveat 1).

## Conclusion

`ReentrancyGuard` is **not vulnerable**: the mutex is a correct non-zero-sentinel
lock at a collision-safe namespaced slot. Its value is bounded and honest — it stops
*same-contract* re-entry only. The reviewer's job in any consumer is to confirm the
contract still follows checks-effects-interactions and that read-only/cross-contract
reentrancy paths (which this guard cannot see) are independently handled.
