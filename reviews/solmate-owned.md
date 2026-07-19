# Security Review — Solmate Owned

**Target:** [transmissions11/solmate](https://github.com/transmissions11/solmate/blob/main/src/auth/Owned.sol) — `Owned` (Solidity ≥0.8.0, MIT), pinned commit [`89365b8`](https://github.com/transmissions11/solmate/commit/89365b880c4f3c786bdd453d4b8e8fe410344a69)
**Type:** Single-owner access-control mixin (37 lines)
**Method:** Static, line-by-line review of the pinned raw source, cross-checked against OpenZeppelin's current `Ownable.sol` (master, same fetch date) for the specific design choices called out below
**Outcome:** **No vulnerability in the contract as written.** Its logic does exactly
what it claims — one storage slot, one `require`, one setter — and every line
behaves correctly for that scope. The genuine review finding is that this scope is
*narrower* than what integrators coming from OpenZeppelin's `Ownable` will assume,
and the gap is a real, verified foot-gun rather than a hypothetical one.

## What it does

```solidity
address public owner;

modifier onlyOwner() virtual {
    require(msg.sender == owner, "UNAUTHORIZED");
    _;
}

constructor(address _owner) {
    owner = _owner;
    emit OwnershipTransferred(address(0), _owner);
}

function transferOwnership(address newOwner) public virtual onlyOwner {
    owner = newOwner;
    emit OwnershipTransferred(msg.sender, newOwner);
}
```

That is the entire contract. One public `address` slot, a `virtual` modifier that
gates on `msg.sender == owner`, a constructor that sets the initial owner, and a
`virtual` `transferOwnership` that lets the current owner overwrite the slot.

## Line-by-line

- **`owner` (public storage slot).** Plain `address`, no diamond-storage namespacing.
  Correct for a base contract meant to be inherited directly into a single
  implementation. **Caveat:** if `Owned` is combined with an upgradeable-proxy
  pattern, slot 0 (or wherever `owner` lands) is subject to the same
  inheritance-order storage-layout fragility as any non-namespaced state variable —
  not a bug in this file, but a real constraint on how it may be composed.
- **`onlyOwner` modifier (line 20–24).** `require(msg.sender == owner, ...)` is the
  textbook correct check — no signature/delegatecall confusion, no `tx.origin`. It's
  declared `virtual`, so a derived contract *can* override it to weaken or bypass the
  check; that is an explicit design affordance (documented nowhere in this file, but
  standard Solidity semantics), not a flaw in `Owned` itself — the trust boundary
  shifts to "whoever writes the derived contract."
- **Constructor (line 30–33).** Sets `owner = _owner` and emits
  `OwnershipTransferred(address(0), _owner)` unconditionally. **No check that
  `_owner != address(0)`.** Compare OpenZeppelin's current `Ownable`, which reverts
  with `OwnableInvalidOwner` in the constructor if `initialOwner == address(0)`
  (verified in `Ownable.sol` master, fetched same session). If a deployer passes
  `address(0)` here — e.g. a misconfigured deploy script, or a constructor argument
  computed from a variable that's still unset — the contract is born with **no
  owner ever able to call `onlyOwner` functions**, including `transferOwnership`
  itself. There is no recovery path from inside the contract.
- **`transferOwnership` (line 39–42).** `onlyOwner`-gated, sets `owner = newOwner`,
  emits the event. **No check that `newOwner != address(0)`**, and **no two-step
  accept/pending-owner pattern.** Compare OZ `Ownable`: its `transferOwnership` also
  reverts on `address(0)` (a caller who genuinely wants to renounce must call the
  separate, explicitly-named `renounceOwnership()`), and OZ additionally ships
  `Ownable2Step` for protocols that want a pending-owner handshake. Solmate's
  `Owned` has neither guard. A single fat-fingered address (zero, or simply the
  wrong address) in a `transferOwnership` call permanently locks out every
  `onlyOwner` function — there is no way for `msg.sender` to ever equal
  `address(0)` in a real transaction (no private key exists for it), so this is not
  a "revocable mistake," it's terminal.

## Why this isn't classified as a vulnerability

`Owned`'s NatSpec calls it a "simple single owner authorization mixin," and every
line matches that description — it does not claim to validate `newOwner`, does not
claim a two-step handshake, and does not claim renounce semantics distinct from a
zero-address transfer. Nothing in the code contradicts its own documentation, and
`msg.sender == owner` — the one security-critical comparison — is correct on every
path. This is a scope/API-safety gap relative to a *different* library
(OpenZeppelin's `Ownable`), not an internal logic bug. Solmate's stated design
philosophy across the repo is minimal gas-optimized primitives that push extra
safety checks to the integrator; this file is consistent with that philosophy.

## Caveats an integrator must respect (not library bugs — real, verified footguns)

1. **Zero-address is not rejected anywhere.** Both the constructor and
   `transferOwnership` will silently accept `address(0)` and permanently disable
   every `onlyOwner`-gated function in the inheriting contract, with no distinct
   "intentional renounce" signal in the code (the emitted event looks identical to
   any other transfer). If a caller wants to be able to safely renounce, or wants
   the deploy/ops tooling to catch a zero-address typo before it lands on-chain,
   that check must be added in the derived contract or enforced off-chain before
   the transaction is sent.
2. **No two-step ownership transfer.** A `transferOwnership` call is final the
   moment it's mined. There is no `pendingOwner` / `acceptOwnership()` handshake to
   catch a wrong-address typo before it takes effect (unlike OZ's `Ownable2Step`).
   Protocols that consider ownership transfer a high-stakes operation should wrap
   `transferOwnership` in their own two-step logic rather than call it directly.
3. **`onlyOwner` and `transferOwnership` are both `virtual`.** Intentional and
   useful for legitimate overrides (e.g. adding a timelock), but it also means the
   security guarantee of any specific deployment depends on auditing the *most
   derived* contract, not `Owned.sol` in isolation — an override could silently
   change or remove the access check.
4. **No `Ownable2Step`-style rejection of transferring to `owner` itself**, and no
   event-based way to distinguish a genuine renounce from an accidental
   zero-address transfer after the fact — both emit the same
   `OwnershipTransferred` shape. Off-chain monitoring that assumes "transfer to
   `address(0)`" always means an intentional renounce should not rely on this
   contract to make that distinction; it doesn't.

## Conclusion

`Owned` is **not vulnerable**: its 37 lines do precisely what they claim, and the
one security-relevant comparison (`msg.sender == owner`) is implemented correctly
with no edge case that breaks it. The real review value here is naming what this
minimal contract does *not* do relative to the more defensive `Ownable` /
`Ownable2Step` that many integrators mentally default to: no zero-address guard on
either the constructor or `transferOwnership`, and no two-step handshake. Both gaps
are verified against OpenZeppelin's current source, not assumed — and both are the
kind of gap that has caused real-world ownership-bricking incidents when teams
assume gas-optimized libraries carry the same safety rails as their more defensive
counterparts.
