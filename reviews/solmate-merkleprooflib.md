# Security Review — Solmate MerkleProofLib

**Target:** [transmissions11/solmate](https://github.com/transmissions11/solmate/blob/f2833c7cc951c50e0b5fd7e505571fddc10c8f77/src/utils/MerkleProofLib.sol) — `MerkleProofLib` (Solidity ≥0.8.0, AGPL-3.0), pinned at commit `f2833c7` ("Memory safe assembly", 2022-10-27, last commit to touch this file)
**Type:** Gas-optimized single-proof Merkle inclusion verification, pure assembly
**Method:** Static, line-by-line review of the pinned raw source (48 lines — the entire file)
**Outcome:** **No vulnerability in the library.** The single `verify` function correctly
reimplements commutative sorted-pair hashing in assembly, the scratch-space memory
usage is safe under the `memory-safe-assembly` annotation, and the empty-proof edge
case resolves correctly. The real risks are the same class of integrator footguns
that apply to any Merkle-proof library — most importantly the second-preimage
attack, which this library (like every other) cannot enforce against.

## What it does

One function, `verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) → bool`.
No storage, no external calls, no other functions — the entire attack surface is
this one pure computation.

## The core loop — correct

```solidity
assembly {
    if proof.length {
        let end := add(proof.offset, shl(5, proof.length))
        let offset := proof.offset
        for {} 1 {} {
            let leafSlot := shl(5, gt(leaf, calldataload(offset)))
            mstore(leafSlot, leaf)
            mstore(xor(leafSlot, 32), calldataload(offset))
            leaf := keccak256(0, 64)
            offset := add(offset, 32)
            if iszero(lt(offset, end)) { break }
        }
    }
    isValid := eq(leaf, root)
}
```

Decoded against OpenZeppelin's `commutativeKeccak256(a, b)` (already reviewed in
[openzeppelin-merkleproof.md](openzeppelin-merkleproof.md)) for comparison:

- **Sort-before-hash, done via scratch-space slot selection instead of a branch.**
  `gt(leaf, calldataload(offset))` computes which of the two 32-byte words is
  larger; `leafSlot` becomes `32` if `leaf` is the larger word, else `0`. `leaf`
  is stored at `leafSlot` and the sibling at the other slot (`xor(leafSlot, 32)`
  flips 0↔32). This places the smaller word at address `0x00` and the larger at
  `0x20` in every case — semantically identical to OZ's `a < b ? (a,b) : (b,a)`
  sorted-pair ordering, just computed without a conditional jump. ✔
- **Scratch space is the correct, memory-safe place for this.** Solidity reserves
  `0x00`–`0x40` as always-available scratch space regardless of the free-memory
  pointer; writing there and hashing `keccak256(0, 64)` is exactly the documented
  safe use, which is why `/// @solidity memory-safe-assembly` is a truthful
  annotation here (verified against the two `mstore`s only ever touching
  `0x00`/`0x20`, never `0x40`+, so the free memory pointer at `0x40` is never
  clobbered). ✔
- **Calldata array bounds.** `proof.offset`/`proof.length` are Solidity's own
  calldata-array accessors for a `calldata` parameter — the ABI decoder already
  validates the array is well-formed before the function body runs, so `offset`
  never reads past the actual proof data within `[proof.offset, end)`. ✔
- **Loop termination.** `end` is computed once from `proof.length`; the loop
  advances `offset` by 32 every iteration and breaks when `offset >= end` — a
  standard bounded `do-while`, runs exactly `proof.length` times, no off-by-one
  (verified: for `proof.length == 1`, `end = proof.offset + 32`; after one
  iteration `offset = proof.offset + 32 = end`, loop breaks). ✔
- **Empty-proof edge case.** If `proof.length == 0`, the `if proof.length { … }`
  block is skipped entirely, `leaf` is left unmodified, and line "`isValid := eq(leaf, root)`"
  still executes (it sits **outside** the `if`, at the same assembly-block level).
  So `verify([], root, leaf)` returns `true` iff `leaf == root` — the correct
  behavior for proving membership in a single-leaf (depth-0) tree, not a bug. ✔

**Verdict: the hashing and control flow are correct; this is a faithful,
gas-optimized reimplementation of sorted-pair Merkle verification with no logic
divergence from the reference (OZ) semantics.**

## No multiproof — not a gap, a smaller attack surface

Unlike OpenZeppelin's `MerkleProof.sol`, this library has **no `multiProofVerify`
equivalent** — only single-leaf `verify`. That means the 2023 OZ multiproof forgery
advisory (crafted `proof`/`proofFlags` validating leaves never in the tree) has no
applicable code path here at all; there is nothing to patch because the feature
doesn't exist. Worth flagging explicitly for anyone porting from OZ's multiproof API
to this library: **feature parity is not assumed** — batch-proof logic must be
re-verified independently if reintroduced, not copied over as if this file already
handles it.

## Integration footguns (where real exploits live — same class as every Merkle-proof library)

1. **Second-preimage attack — the critical one, unenforceable by this library.**
   `verify` hashes whatever `leaf` it's given with siblings, exactly as designed.
   If a consumer hashes leaves the same way internal nodes are hashed
   (`keccak256` of two 32-byte words) and doesn't domain-separate, an attacker can
   present an **internal node's hash as a "leaf"** and forge inclusion of data that
   was never a real leaf. This library has **no NatSpec warning about this at all**
   (unlike OZ's, which documents it at the top of the file) — so an integrator who
   only reads this file's comments gets no hint. The mitigation is unchanged from
   the OZ review: **double-hash leaves** before building the tree /
   verifying (`keccak256(bytes.concat(keccak256(abi.encode(leafData))))`), so a
   leaf preimage can never collide with a 64-byte internal-node preimage.
2. **Tree must be built with this exact sort-before-hash convention.** Because the
   pair ordering is `min(a,b)` at `0x00`, `max(a,b)` at `0x20`, a tree constructed
   with position-dependent (left/right) hashing — or sorted differently, e.g. by
   a different comparator — will simply never verify. This is silent: `verify`
   returns `false`, not a revert with a reason, so debugging a mismatched tree
   construction looks identical to debugging a genuinely invalid proof.
3. **`calldata`-only signature.** `proof` is typed `bytes32[] calldata`, so a
   caller holding the proof in `memory` (e.g. reconstructed on-chain, or passed
   through an internal function boundary) cannot call `verify` directly — it must
   be exposed through an `external`/`calldata`-typed entry point. Not a bug, but a
   real integration constraint absent from the OZ version (which takes `memory`).
4. **No replay/consumption protection**, identically to every other Merkle-proof
   library: a valid proof stays valid forever. One-time-claim semantics (e.g. a
   claimed-bitmap for an airdrop) are entirely the caller's responsibility.
5. **No leaf-emptiness or root-zero guard.** `verify(proof, bytes32(0), bytes32(0))`
   with an empty proof returns `true` (0 == 0). If a consumer ever leaves `root`
   uninitialized (default `bytes32(0)`) before it's set, *any* caller can "prove"
   membership of the zero leaf with an empty proof. This is a caller-side
   initialization bug, not a library bug — but it's a concrete, exploitable pattern
   worth checking for in any consumer of this file.

## Conclusion

`MerkleProofLib` is **not vulnerable**: its assembly correctly reimplements
commutative sorted-pair Merkle verification, scratch-space usage is genuinely
memory-safe, and the empty-proof edge case resolves to the mathematically correct
answer rather than an unintended bypass. Because it is a bare 48-line pure function
with no multiproof surface, it is also structurally immune to the class of bug that
hit OZ's multiproof path in 2023. The review's actionable value is entirely in the
integration checklist above — especially that **this file, unlike OZ's, documents
none of the second-preimage risk in its own comments**, so a consumer that trusts
the file's brevity as a signal of safety is the most likely real-world failure mode.
