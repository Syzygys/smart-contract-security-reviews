# Security Review — Solmate ReentrancyGuard

**Target:** [transmissions11/solmate](https://github.com/transmissions11/solmate/blob/89365b880c4f3c786bdd453d4b8e8fe410344a69/src/utils/ReentrancyGuard.sol) — `ReentrancyGuard` (pinned commit `89365b8`, 19 lines, AGPL-3.0-only)
**Type:** Reentrancy-protection base contract (`nonReentrant` modifier)
**Method:** Static, line-by-line review of the pinned raw source, cross-checked
against the already-reviewed [OpenZeppelin ReentrancyGuard](openzeppelin-reentrancyguard.md)
(same job, different implementation choices)
**Outcome:** **No vulnerability found.** The lock logic is a correct, minimal
non-zero-sentinel mutex. The interesting content is a real, code-verified design
difference from OZ's version — the modifier is declared `virtual` — which is a
genuine footgun, not present in the OZ implementation.

## The full contract

```solidity
abstract contract ReentrancyGuard {
    uint256 private locked = 1;

    modifier nonReentrant() virtual {
        require(locked == 1, "REENTRANCY");

        locked = 2;

        _;

        locked = 1;
    }
}
```

## The lock — correct

- `locked` (L8) is a plain `uint256` storage slot, initialized to `1` at
  declaration rather than left at the default `0`.
- The modifier (L10-18): `require(locked == 1, ...)` (L11) reverts if already
  entered; sets `locked = 2` (L13); runs the guarded body (`_;`, L15); resets
  `locked = 1` (L17).
- **Non-zero sentinel (`1`/`2` instead of `0`/`1`).** Same rationale as OZ's
  version: the guard's "unlocked" state is never the default zero slot, so every
  guarded call is a non-zero→non-zero `SSTORE` (cheaper than the zero→non-zero
  case), and resetting to `1` after use qualifies for the gas refund. Verified
  correct — no state confusion between "never initialized" and "unlocked."
- **Atomicity.** EVM execution is single-threaded per transaction, so there is no
  window between `locked = 2` (L13) and the check at L11 where another call can
  interleave — the classic TOCTOU concern does not apply on-chain. If the guarded
  body (`_;`) reverts, the whole call (including the `locked = 2` write) reverts
  with it, so a failed call can never leave the guard stuck at `2`. Verified by
  tracing both the success path (L13→L15→L17, unconditionally reached since `_;`
  either completes or reverts the whole frame) and the revert path (no state
  persists).

**Verdict: the mutex itself is correct — entry during an active guard reverts,
and it self-resets on every code path that doesn't revert the whole transaction.**

## Where this differs from OpenZeppelin's version (the real content of this review)

Solmate's own `@author` comment (L6) says it was "Modified from OpenZeppelin," so
the natural review question is: modified *how*, and does the modification change
the security properties? Three concrete, verified differences:

1. **`modifier nonReentrant() virtual` (L10) — OZ's is not `virtual`.** Checked
   directly against the OZ v5.6.1 source reviewed separately
   ([openzeppelin-reentrancyguard.md](openzeppelin-reentrancyguard.md)): OZ declares
   `modifier nonReentrant() { _nonReentrantBefore(); _; _nonReentrantAfter(); }`
   with no `virtual` keyword, so it cannot be overridden. Solmate's `virtual` means
   any derived contract can supply its own `nonReentrant` body via
   `modifier nonReentrant() override { ... }` and Solidity accepts it — the
   compiler enforces nothing about what the override actually does. A derived
   contract that overrides it with, say, `modifier nonReentrant() override { _; }`
   (no lock at all) compiles cleanly and silently removes reentrancy protection
   from every function that uses `nonReentrant`, with no warning at the call site.
   This is real, verifiable Solidity modifier-override semantics (available since
   the pragma floor here, `>=0.8.0`), not a hypothetical — it is the direct
   consequence of the `virtual` keyword Solmate chose to add. **This is the
   integrator-facing footgun this review exists to flag**: `virtual` here is a
   feature (lets a fork swap in transient-storage-based locking, a custom error,
   etc.) that is simultaneously a silent-disable risk if a derived contract's
   override is wrong or incomplete.
2. **Plain, non-namespaced storage slot.** `uint256 private locked` (L8) is an
   ordinary state variable — its storage slot is whatever the compiler assigns
   given the contract's linearized inheritance order at compile time. OZ's current
   version instead keeps its status flag at an explicit ERC-7201-derived slot
   (verified in the earlier OZ review) specifically to survive upgradeable/diamond
   storage layouts safely. Solmate's plain-variable approach is fine for a single
   compiled, non-upgradeable deployment (the normal Solmate use case), but a team
   that inherits this guard into a proxy-upgradeable contract and later reorders or
   inserts base contracts before `ReentrancyGuard` in the inheritance list risks a
   storage collision on upgrade — a risk this file does nothing to prevent, unlike
   OZ's namespaced version.
3. **Plain `require(..., "REENTRANCY")` instead of a custom error.** Functionally
   identical (both revert), just a minor gas/tooling difference — OZ's
   `ReentrancyGuardReentrantCall()` custom error is ~4 bytes of revert data vs. the
   string's ABI-encoded bytes; not a security difference.

## What this guard does not protect against (same limits as any per-contract mutex)

Same caveat class as the OZ review, verified again here since it's inherent to
the design, not specific to either implementation:
- **Cross-contract and read-only reentrancy.** The lock is local to this
  contract's storage. If a guarded function calls out to another contract, and
  that contract (or a further callee) reads *this* contract's state while it's
  mid-update, `locked` never stops that read — there is no `nonReentrantView`
  equivalent here at all (Solmate omits even the partial mitigation OZ offers).
  Checks-effects-interactions ordering in the guarded function remains the
  caller's responsibility, entirely outside what this 19-line file can enforce.
- **Same-contract nested `nonReentrant` calls revert.** Calling one
  `nonReentrant` function from another in the same contract hits the `require` at
  L11 and reverts, identical to OZ's behavior — by design, not a bug, but worth
  knowing before composing two guarded entry points.

## Conclusion

`ReentrancyGuard` is **not vulnerable**: the lock correctly blocks same-contract
re-entry using a standard non-zero-sentinel mutex, and resets cleanly on every
non-reverting path. The genuine review finding is the `virtual` modifier
(L10) — a deliberate design choice, verified absent in OZ's equivalent — that
gives downstream contracts the power to silently disable the guard via an
incomplete override, with the compiler offering no protection against that
mistake. An integrator adopting this base contract should audit any subclass
that declares `override` on `nonReentrant`, and should not assume "inherits
ReentrancyGuard" alone guarantees the lock is actually active.
