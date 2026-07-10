# Security Review — OpenZeppelin MerkleProof

**Target:** [OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MerkleProof.sol) — `MerkleProof` (Solidity, MIT)
**Type:** Merkle inclusion-proof verification (single proof + multiproof)
**Method:** Static, line-by-line review of the pinned raw source (510 lines)
**Outcome:** **No vulnerability in the library.** The single-proof path is a correct
commutative-hash climb; the multiproof path carries the fix for the 2023 multiproof
forgery advisory. The decisive risks are **integration footguns** — above all the
Merkle second-preimage attack, which the library documents but cannot enforce.

## Single proof — correct

```solidity
function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
    bytes32 computedHash = leaf;
    for (uint256 i = 0; i < proof.length; i++)
        computedHash = Hashes.commutativeKeccak256(computedHash, proof[i]);
    return computedHash;
}
```
`commutativeKeccak256` sorts the two 32-byte words before hashing, so the proof does
not carry left/right position — hence the NatSpec "each pair … is assumed to be
sorted." `verify` returns `processProof(...) == root`. Correct and minimal. ✔

## Multiproof — the 2023 forgery bug is fixed

`processMultiProof` rebuilds the root from a queue of `leaves` then `hashes`,
consuming `proof`/`proofFlags`. It enforces **two invariants** that together close
the historical multiproof forgery (where crafted proof/flags could validate leaves
not in the tree):

1. **Length invariant** (up front):
   `if (leavesLen + proof.length != proofFlagsLen + 1) revert MerkleProofInvalidMultiproof();`
2. **Full-consumption check** (at the end):
   `if (proofPos != proof.length) revert MerkleProofInvalidMultiproof();`

The second is the key fix: without it, leftover unconsumed `proof` elements let an
attacker smuggle in unrelated hashes. With both checks, a well-formed run consumes
exactly the declared elements. ✔ The `CAUTION: Not all Merkle trees admit
multiproofs` and `leaves must be validated independently` notes are correct and
load-bearing (see footgun 2).

**Verdict: the verification logic is correct; the known multiproof weakness is patched.**

## Integration footguns (where real exploits live)

1. **Second-preimage attack — the critical one.** Because internal nodes are
   `keccak256(64 bytes)` and a naively-hashed leaf can also be 64 bytes, an attacker
   can present an **internal node as if it were a leaf** and prove membership of data
   that was never a leaf. The library's top-of-file NatSpec warns to hash leaves
   distinctly. The standard mitigation (and what OZ's own tooling does) is to
   **double-hash leaves**: `keccak256(bytes.concat(keccak256(abi.encode(leaf))))`,
   guaranteeing a leaf preimage can never collide with a 64-byte node. This is the
   famous, repeatedly-exploited airdrop/allowlist bug. `MerkleProof` **cannot enforce
   it** — it is entirely the integrator's responsibility, and it is the first thing a
   reviewer must check in any consumer of this library.
2. **`leaves` must be validated independently (multiproof).** The multiproof
   functions do not verify that the supplied `leaves` are genuine, distinct leaf
   hashes. A caller that trusts attacker-supplied leaves — combined with a weak
   leaf-hashing scheme (footgun 1) — can be tricked. Validate leaf provenance
   yourself.
3. **Tree must be built with the same commutative (sorted-pair) hashing.** A tree
   constructed with position-dependent hashing will not verify here, and commutative
   hashing means leaf position carries no meaning — do not encode ordering
   assumptions into proofs.
4. **Proofs are not replay/nonce protection.** A valid inclusion proof stays valid
   forever; consuming-once (e.g. a claimed-bitmap) is the caller's job, exactly as
   with signatures.

## Conclusion

`MerkleProof` is **not vulnerable**: single-proof verification is correct and the
multiproof path enforces the length + full-consumption invariants that fix the 2023
forgery class. The actionable review output is the integration guidance — most
importantly, **hash leaves distinctly from internal nodes (double-hash)** to defeat
the second-preimage attack, and **validate leaf provenance** before trusting a
multiproof. These are the points that decide whether a *consumer* of this library is
safe.
