# Security Review — Uniswap Permit2

**Target:** [Uniswap/permit2](https://github.com/Uniswap/permit2) (Solidity 0.8.17)
**Type:** ERC-20 approval / signature-transfer infrastructure
**Method:** Static, line-by-line review against a pinned snapshot (commit `cc56ad0`)
**Outcome:** **No reportable vulnerability.** Three attack paths analysed to
definitive verdicts.
**Scope note:** Public code only, read-only. Permit2 is mature, multiply-audited
infrastructure; the goal here was a defensible verdict on three specific paths, not
a full audit contest submission.

## Contracts in scope

`Permit2` composes two independent modules over a shared `EIP712` domain:

- `AllowanceTransfer` — stored, time-bounded allowances
  (`allowance[owner][token][spender] -> PackedAllowance{amount:uint160,
  expiration:uint48, nonce:uint48}`)
- `SignatureTransfer` — one-shot signed transfers with an unordered nonce bitmap
  (`nonceBitmap[owner][wordPos]`)
- Libraries: `Allowance`, `PermitHash`, `SignatureVerification`

Trust model: users first `approve` Permit2 on the ERC-20; Permit2 then gates
`spender` via stored allowance or signature. `owner` may be an EOA or ERC-1271
contract wallet. Tokens are fully external and are **not** assumed honest. There is
no owner/admin/upgrade path — so the risk surface is signature domain, nonce
consumption, allowance state transitions, and external token behaviour.

## Path 1 — SignatureTransfer nonce ordering + reentrant token → **not a vulnerability**

`SignatureTransfer._permitTransferFrom` (L58–67) orders operations:
check deadline → check amount → `_useUnorderedNonce(owner, permit.nonce)` (L63) →
`signature.verify` (L65) → `safeTransferFrom` (L67).

`_useUnorderedNonce` (L150–156) flips the nonce bit and reverts on reuse:
`flipped = nonceBitmap[from][wordPos] ^= bit; if (flipped & bit == 0) revert InvalidNonce();`

Reasoning:
- The nonce is **consumed before the external token call** — correct
  checks-effects-interactions ordering. A malicious token reentering during
  `safeTransferFrom` with the *same* nonce hits an already-set bit and reverts;
  with a *different* valid signature+nonce it is merely another legitimate op, not
  an exploit.
- The nonce is consumed before `signature.verify`, but a valid-nonce/invalid-sig
  call reverts at verify and the whole transaction atomically rolls back — the bit
  flip rolls back with it, so there is no nonce-griefing.
- The batch path (L99–127) consumes the nonce once for the batch; reentry with the
  same nonce necessarily reverts.

**Verdict:** correct ordering; atomic rollback preserves nonce integrity. Not a
vulnerability.

## Path 2 — AllowanceTransfer packed-allowance state machine → **not a vulnerability**

`AllowanceTransfer._transfer` (L76–94): reverts if `block.timestamp > allowed.expiration`
(L79); for non-`uint160.max` allowances, reverts if `amount > maxAmount`, else
`allowed.amount = maxAmount - amount` (L82–89, underflow-safe since `amount ≤ maxAmount`);
`uint160.max` is treated as infinite and not decremented (intentional gas optimisation).

`_updateApproval` (L131–142) reverts if `allowed.nonce != nonce` (L138) then
`updateAll(...)`. `Allowance.updateAll` (L13–30) sets `storedNonce = nonce + 1`
(unchecked), maps `expiration == 0 → block.timestamp`, and `sstore`s the whole
packed word (`nonce<<208 | expiration<<160 | amount`, exactly 256 bits).
`invalidateNonces` (L113–126) requires `newNonce > oldNonce` and `delta ≤ uint16.max`.

Reasoning: the three invariants hold — expired allowances are unusable, non-infinite
allowances decrement exactly and underflow-safely, and nonces are monotonic. The
only theoretical concern is the unchecked `nonce + 1` wrapping at `uint48.max`
(potentially re-enabling a nonce-0 signature) — but reaching `2^48 ≈ 2.8×10^14`
permits for a single owner/token/spender triple is economically and gas-infeasible,
and is an industry-accepted pattern.

**Verdict:** not a vulnerability.

## Path 3 — Witness type string / EIP-712 domain binding → **not a contract vulnerability (integration/UX risk)**

`PermitHash.hashWithWitness` (L85–94): `typeHash = keccak256(abi.encodePacked(STUB, witnessTypeString))`,
where the STUB (L31–32) ends in a comma with no closing paren and is completed by the
integrator-supplied `witnessTypeString`; the final hash is
`keccak256(abi.encode(typeHash, tokenPermissionsHash, msg.sender, permit.nonce, permit.deadline, witness))`.

Reasoning:
- The core transfer parameters (permitted token/amount, `spender = msg.sender`,
  nonce, deadline) are hashed **independently of the witness**.
- `witnessTypeString` is *committed* by the signature — redemption must supply the
  same string to reproduce the same hash, else `signature.verify` reverts on signer
  mismatch. An attacker cannot swap in a different `witnessTypeString` for the same
  signature.
- `msg.sender` written into the hash (L93) binds the spender, preventing signature
  reuse by another spender. The witness is additive data that cannot change core
  transfer semantics (bounded by `permit.permitted` and `requestedAmount ≤ permitted.amount`).

**Verdict:** not a Permit2 contract vulnerability. The real risk is at the
integration layer — an integrator accepting an untrusted `witnessTypeString`, or a
wallet displaying an opaque witness type unclearly. Permit2 explicitly delegates
`witnessTypeString` correctness to integrators (recommended practice: hardcode your
own). This is documented behaviour, not a contract defect.

## Conclusion

All three paths were analysed to definitive verdicts; **no reportable
vulnerability** was found. Each verdict follows from code structure plus EVM /
signature semantics (atomicity, CEI ordering, hash-commitment), so it stands without
dynamic PoC — though pinning down Path 1's reentrancy disproof to a reproducible
Foundry test with a malicious token would further harden the conclusion (direction
unchanged).

For heavily-audited infrastructure like Permit2, "reviewed to a defensible no-bug
verdict" is the correct and honest outcome — the review does not manufacture a
finding to appear productive.
