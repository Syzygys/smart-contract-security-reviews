# Security Review — OpenZeppelin `Address` (+ `LowLevelCall` backend)

**Target:** [OpenZeppelin/openzeppelin-contracts @ v5.6.1](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/Address.sol) —
`contracts/utils/Address.sol` (167 lines), plus its two direct dependencies
`contracts/utils/LowLevelCall.sol` (127 lines) and `contracts/utils/Errors.sol`
(34 lines). MIT license. v5.6.1 is the current tagged release (published
2026-02-27); confirmed byte-identical against the `master` branch at review
time, so this is shipped, in-production code, not a work-in-progress branch.
**Type:** Low-level `call`/`staticcall`/`delegatecall` wrapper library — the
most widely inherited "trust boundary" primitive in the OZ stack (used by
`Clones`, `SafeERC20`, proxy patterns, and effectively any contract that makes
an untrusted external call).
**Method:** Static, line-by-line review of all three files together — `Address`
alone can't be judged correctly in isolation, since v5.5.0 refactored it from
inline assembly to delegate the actual `CALL`/`RETURNDATACOPY`/`REVERT`
mechanics to `LowLevelCall`. Reviewing only the wrapper would have missed
where the real correctness guarantees live.
**Outcome:** **No vulnerability found.** The classic "call to non-contract
silently succeeds" footgun is correctly closed on every code path, and the
`LowLevelCall` assembly primitives are memory-safe. One documented-footgun
class is flagged for integrators (reentrancy, unchanged from prior versions)
plus a minor, non-exploitable memory-layout note.

## What it does

`Address` exposes six functions used to make untrusted external calls safely:
`sendValue` (ETH transfer, no gas stipend), `functionCall` /
`functionCallWithValue` (call + data), `functionStaticCall`,
`functionDelegateCall`, and two `verifyCallResult*` helpers for callers who
already performed their own `.call()`. Since v5.5.0 these no longer contain
raw `assembly` blocks themselves — they call into `LowLevelCall`, a separate
library of primitives (`callNoReturn`, `staticcallNoReturn`,
`delegatecallNoReturn`, `returnDataSize`, `returnData`, `bubbleRevert`).

## The core invariant: no false "success" against a non-contract

The classic bug class this library exists to prevent: a low-level `call` to
an address with no code always returns `success = true` with empty return
data (the EVM has nothing to execute, so there's nothing to fail). Naive code
that treats `success == true` as "the call did what I asked" gets silently
no-op'd against typo'd addresses, not-yet-deployed proxies, or
self-destructed contracts.

Every `function*Call` in `Address.sol` uses the same guard
(`functionCallWithValue`, [Address.sol:83-92](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/Address.sol#L83-L92)):

```solidity
bool success = LowLevelCall.callNoReturn(target, value, data);
if (success && (LowLevelCall.returnDataSize() > 0 || target.code.length > 0)) {
    return LowLevelCall.returnData();
} else if (success) {
    revert AddressEmptyCode(target);
} else if (LowLevelCall.returnDataSize() > 0) {
    LowLevelCall.bubbleRevert();
} else {
    revert Errors.FailedCall();
}
```

Traced against every outcome:
- **Reverted** → `success = false`, `returnDataSize() > 0` (revert reason
  present) → `bubbleRevert()` propagates the real reason. ✔
- **Reverted with no reason** (e.g. out-of-gas, or `revert()` with no data) →
  `success = false`, `returnDataSize() == 0` → `Errors.FailedCall()`. ✔
- **Succeeded, target has code, returned data** → first branch, data
  returned directly. ✔
- **Succeeded, target has code, returned nothing** (a valid `void` function) →
  `returnDataSize() == 0` but `target.code.length > 0` → still takes the
  first branch via the `OR`. ✔ This is the case a naïve
  `returnDataSize() > 0` check alone would get wrong.
- **Succeeded, target is an EOA / no code** (the dangerous case) →
  `returnDataSize() == 0 AND target.code.length == 0` → falls through to
  `else if (success)` → **reverts `AddressEmptyCode`.** ✔ This is exactly the
  case the library exists to catch, and it's closed.

`functionStaticCall` ([L99-L110](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/Address.sol#L99-L110)) and
`functionDelegateCall` ([L116-L127](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/Address.sol#L116-L127))
use the identical four-way branch, just swapping `LowLevelCall.callNoReturn`
for `staticcallNoReturn` / `delegatecallNoReturn`. No divergence, no missed
case.

`sendValue` ([L34-L46](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/Address.sol#L34-L46))
is the same pattern minus the contract-code check (ETH sends succeed against
EOAs by design, so `AddressEmptyCode` doesn't apply): balance-checked
up front, then reverts with the bubbled reason or `FailedCall()` on failure.

## Why the guard doesn't have a self-destruct bypass

A plausible attack shape: get `target` to `SELFDESTRUCT` *during* the call
being made, so that the post-call `target.code.length` read sees zero and the
call looks like it hit an EOA even though it actually executed code.

This doesn't break the guard, for two independent reasons: (1) since
[EIP-6780](https://eips.ethereum.org/EIPS/eip-6780) (Cancun), `SELFDESTRUCT`
only clears code/storage if the contract was *created in the same
transaction* — on any mainnet/L2 past Cancun this path is already closed for
normal contracts; (2) even where it isn't (older EVM forks, or the
same-tx-creation edge case), the guard fails **closed**: if `target` really
had code and self-destructed leaving no return data, `success=true`,
`returnDataSize()==0`, `code.length==0` → the call reverts with
`AddressEmptyCode` rather than silently succeeding. The worst case is an
unnecessary revert on a real call that happened, not a bypassed check.
**Verified: not exploitable, fails safe.**

## `LowLevelCall` primitives — memory-safety check

The `assembly ("memory-safe")` blocks were checked individually:

- `callNoReturn`/`staticcallNoReturn`/`delegatecallNoReturn`
  ([L19-23, 51-55, 74-78](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/LowLevelCall.sol#L19-L23))
  pass `0x00, 0x00` as the out-region to the `CALL`-family opcode. This does
  **not** lose the return data — `RETURNDATASIZE`/`RETURNDATACOPY` read the
  EVM's internal return buffer independent of what out-region the call site
  requested, so `returnDataSize()`/`returnData()` called afterward still see
  the real data. Correct.
- `returnData()` ([L104-111](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/LowLevelCall.sol#L104-L111))
  builds a `bytes memory` at the free memory pointer, writes the length,
  `returndatacopy`s the payload, then bumps FMP by exactly
  `0x20 + returndatasize()` — **not** rounded up to a 32-byte multiple.
  Solidity's memory-safety rules don't require FMP to stay word-aligned (only
  that it point at genuinely unused memory), so this is not a corruption bug.
  Flagged below as a minor integrator-facing note, not a vulnerability.
- `bubbleRevert()` ([L114-119](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/LowLevelCall.sol#L114-L119))
  reads FMP, copies `returndatasize()` bytes of return data there, then
  `revert`s over exactly that range. It never advances FMP after — fine,
  since `revert` terminates execution and nothing reads memory afterward.
  Correct and memory-safe.
- `bubbleRevert(bytes memory returndata)` ([L122-125](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/LowLevelCall.sol#L122-L125))
  reverts directly over the caller-supplied `bytes` payload's data region.
  Only reachable from `verifyCallResultFromTarget`/`verifyCallResult` with
  `returndata` that genuinely came from a prior `.call()`'s return — not
  attacker-constructable into an out-of-bounds revert.
- `callReturn64Bytes`/`staticcallReturn64Bytes`/`delegatecallReturn64Bytes`
  ([L30-48, 62-71, 85-94](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.6.1/contracts/utils/LowLevelCall.sol#L30-L48))
  write into the `0x00-0x40` scratch space, which is explicitly permitted
  under Solidity's memory-safe assembly rules for transient use. These three
  functions are **not called anywhere in `Address.sol`** (they exist for
  other internal OZ callers) — reviewed for completeness since they live in
  the same file and share the trust boundary, but they're out of this
  library's direct call graph.

## Real caveats an integrator must respect (not library bugs)

1. **`sendValue`/`functionCallWithValue` forward all remaining gas, by
   design.** This is explicitly documented in the NatSpec
   ("care must be taken to not create reentrancy vulnerabilities") — it's the
   entire reason `sendValue` exists instead of `.transfer()` (EIP-1884 broke
   the 2300-gas stipend assumption). A caller using these against an
   untrusted `target`/`recipient` without checks-effects-interactions or a
   reentrancy guard is exposed to classic reentrancy — same as every prior
   version of this library, not a regression.
2. **`verifyCallResultFromTarget` is marked DEPRECATED** ("may be removed in
   the next major release") in favor of the `function*Call` family that
   drives the call itself via `LowLevelCall`. Code still depending on it
   should migrate rather than treat it as stable API.
3. **`returnData()`'s free-memory-pointer bump is not 32-byte aligned** when
   `returndatasize() % 32 != 0` (any non-ABI-padded raw return, e.g. a callee
   that does `return(ptr, 7)` directly in assembly). This is memory-safe and
   not exploitable, but integrators who write their own inline assembly
   immediately after a `functionCall`/`functionStaticCall`/
   `functionDelegateCall` return and assume the free memory pointer is
   word-aligned (a common but non-guaranteed assumption) should account for
   this — the same category of caveat as Solmate's
   `SafeTransferLib` documenting its own dirty-memory behavior (see
   [solmate-safetransferlib.md](solmate-safetransferlib.md)).
4. **`AddressEmptyCode` reverts on a "successful" call to an EOA.** This is
   correct and intentional, but it means `functionCall`/`functionCallWithValue`
   cannot be used to send arbitrary calldata to an EOA and treat that as
   success — use `sendValue` for plain ETH transfers to addresses that may
   not be contracts.

## Conclusion

`Address.sol`'s v5.5.0 refactor onto the `LowLevelCall` backend was reviewed
end-to-end rather than trusting the wrapper's NatSpec: every `function*Call`
variant closes the "call succeeds against a non-contract" gap through the
same verified four-way branch, the self-destruct-during-call edge case fails
safe rather than bypassing the guard, and the underlying assembly in
`LowLevelCall` is memory-safe. **No vulnerability found.** The library's real
risk surface, as with `SafeTransferLib`, is entirely on the integrator side —
all-gas-forwarding reentrancy exposure that the NatSpec already documents.
