# Security Review — OpenZeppelin Clones (EIP-1167)

**Target:** [OpenZeppelin/openzeppelin-contracts @ v5.6.1](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/proxy/Clones.sol) — `Clones` (294 lines, MIT)
**Type:** Minimal-proxy (EIP-1167) deployment library — `create` / `create2` clones + deterministic address prediction
**Method:** Static, line-by-line review of the real source (incl. the deployment assembly)
**Outcome:** **No vulnerability found.** The proxy bytecode and `create2` handling are
correct. The decisive content is a set of deployment-time footguns the library
explicitly warns about — most importantly that it does **not** check the
implementation has code, and that deterministic deployment is front-runnable.

## The clone bytecode + deployment — correct

`clone(implementation, value)` (L47-61) and `cloneDeterministic(...)` (L90-108) build
the standard EIP-1167 minimal proxy in memory:

```solidity
mstore(0x00, or(shr(232, shl(96, implementation)), 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000))
mstore(0x20, or(shl(120, implementation), 0x5af43d82803e903d91602b57fd5bf3))
instance := create(value, 0x09, 0x37)          // or create2(value, 0x09, 0x37, salt)
if iszero(instance) { revert Errors.FailedDeployment(); }
```

This is the canonical 55-byte (`0x37`) EIP-1167 runtime that `delegatecall`s to the
20-byte `implementation` address spliced into the two `mstore`s. The `create`/`create2`
result is checked for zero and reverts `FailedDeployment` — so a failed or colliding
deployment can never return a bogus/zero address as if it succeeded. Balance is
pre-checked against `value` (`InsufficientBalance`, L49/L96). ✔

`predictDeterministicAddress` (L114+) recomputes the `create2` address from
`implementation`, `salt`, and the deployer — standard and matches the deploy path.

**Verdict: proxy construction, the zero-address deploy check, and address prediction
are correct.**

## Real deployment footguns (the review's value)

1. **No implementation-code check — stated four times in the NatSpec** (e.g. L28-30,
   L40-42, L71-73, L83). A clone whose `implementation` has **no code** is a proxy
   that `delegatecall`s into nothing: every call returns success with empty data
   (the "call to non-contract silently succeeds" class — cf.
   [openzeppelin-address.md](openzeppelin-address.md)). A factory that clones an
   attacker- or user-supplied `implementation` without a `code.length > 0` check can
   mint permanently-broken or misleading clones. **The caller must validate the
   implementation.**
2. **`cloneDeterministic` is front-runnable (griefing/DoS).** The deployed address is
   a pure function of `(deployer, salt, bytecode)`. Because the bytecode is fixed and
   the deployer is the factory, anyone who can observe a pending
   `cloneDeterministic(impl, salt)` and cause the factory to deploy the **same
   `(impl, salt)`** first will make the victim's call revert (address already
   occupied). If `salt` is attacker-influenceable or predictable, this is a real DoS
   on deterministic-address workflows. Derive `salt` from caller-bound, unpredictable
   inputs, and handle the revert.
3. **Clones are non-upgradeable and forward everything, including value.** The
   minimal proxy has no admin and cannot change implementation. All calls (and ETH
   via the `value` path) are `delegatecall`ed into the implementation using the
   *clone's* storage — so the implementation's logic runs against each clone's own
   state, but any bug or `selfdestruct`-style hazard in the implementation applies to
   every clone. Non-zero-value deployment also requires the factory to hold balance
   (L44-45 NOTE).
4. **`delegatecall` storage-layout coupling.** Because execution is `delegatecall`,
   the implementation contract must be written to operate purely on the clone's
   storage (typical initializer pattern). An implementation with hardcoded
   assumptions about its own deployed state will misbehave when run as a clone's
   logic.

## Conclusion

`Clones` is **not vulnerable**: the EIP-1167 bytecode is canonical, deployment failure
reverts rather than returning a bad address, and deterministic prediction is correct.
The actionable output is deployment hygiene for the *factory* using it — **verify the
implementation has code**, treat `cloneDeterministic` as front-runnable and derive
salts defensively, and remember clones are immutable `delegatecall` proxies whose
safety is inherited entirely from the implementation.
