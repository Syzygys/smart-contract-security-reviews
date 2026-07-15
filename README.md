# Smart Contract Security Reviews

Independent, evidence-based security reviews of smart-contract code — every claim
tied to a specific line, every severity backed by reasoning, and **honest
"no critical finding" conclusions included** rather than hidden.

This portfolio deliberately shows reviews that found *no reportable
vulnerability*, because that is the harder and more honest half of the job:
mature, heavily-audited code usually has no low-hanging bug, and the value of a
reviewer is a defensible verdict — not an invented one. A review that manufactures
findings to look productive is worse than useless; it wastes a protocol's time and
erodes trust.

## Reviews

| Target | Type | Method | Outcome |
|---|---|---|---|
| [Uniswap Permit2](reviews/uniswap-permit2.md) | ERC-20 approval infra (Solidity) | Static, line-by-line | No reportable vulnerability — 3 attack paths analysed to definitive verdicts |
| [Injective swap-contract](reviews/injective-swap-contract.md) | CosmWasm DEX router (Rust) | Static + code hardening | No exploitable vuln; 2 robustness issues found → hardening PR opened upstream |
| [Solmate SafeTransferLib](reviews/solmate-safetransferlib.md) | ERC-20/ETH transfer wrapper (Solidity asm) | Static, line-by-line | No vulnerability; assembly success-check verified correct + 4 integrator footguns named |
| [OpenZeppelin ECDSA](reviews/openzeppelin-ecdsa.md) | Signature recovery library (Solidity) | Static, line-by-line | No vulnerability; malleability + address(0) footguns verified closed; flagged parse() bypass + replay caveat |
| [OpenZeppelin MerkleProof](reviews/openzeppelin-merkleproof.md) | Merkle inclusion-proof library (Solidity) | Static, line-by-line | No vulnerability; 2023 multiproof-forgery fix verified; flagged second-preimage + leaf-validation footguns |
| [OpenZeppelin ReentrancyGuard](reviews/openzeppelin-reentrancyguard.md) | Reentrancy-protection base (Solidity) | Static, line-by-line | No vulnerability; non-zero sentinel + namespaced slot verified; flagged cross-contract/read-only reentrancy gap |
| [OpenZeppelin SafeERC20](reviews/openzeppelin-safeerc20.md) | ERC-20 interaction wrapper (Solidity) | Static, line-by-line | No vulnerability; forceApprove approve-race dance verified; flagged approve-race ≠ solved + read-then-write allowance |
| [OpenZeppelin Clones](reviews/openzeppelin-clones.md) | EIP-1167 minimal-proxy library (Solidity) | Static, line-by-line | No vulnerability; canonical bytecode + create2 verified; flagged no-code-check + front-runnable deterministic deploy |
| [OpenZeppelin Address](reviews/openzeppelin-address.md) | Low-level call wrapper + `LowLevelCall` backend (Solidity asm) | Static, line-by-line | No vulnerability; non-contract-call guard verified closed on all 3 call variants + self-destruct edge case; flagged deprecated API + memory-alignment footgun |
| [Solmate MerkleProofLib](reviews/solmate-merkleprooflib.md) | Single-proof Merkle verification (Solidity asm) | Static, line-by-line | No vulnerability; scratch-space sort-before-hash + empty-proof case verified correct; flagged undocumented second-preimage risk + zero-root footgun |
| [Solmate ERC20](reviews/solmate-erc20.md) | ERC-20 + EIP-2612 permit base contract (Solidity) | Static, line-by-line | No vulnerability; unchecked-arithmetic invariant + ecrecover/domain-separator/malleability all traced and verified; flagged permit front-running + no address(0) guards vs. OZ |
| [Solmate FixedPointMathLib](reviews/solmate-fixedpointmathlib.md) | WAD fixed-point math library — mulDiv, rpow, sqrt (Solidity asm) | Static, line-by-line | No vulnerability; mulDiv overflow guard + rpow squaring loop + sqrt(0) edge case all re-derived and verified; found 1 inverted (non-exploitable) inline comment; flagged phantom-overflow gap vs. OZ Math.mulDiv |
| [Solmate SignedWadMath](reviews/solmate-signedwadmath.md) | Signed wad fixed-point math — mul/div + exp/ln rational approximation (Solidity asm) | Static + dynamic (BigInt re-execution against known math identities) | No vulnerability; wadMul/wadDiv int256 MIN/-1 edge case verified via execution; exp/ln boundary constants verified tight against int256 limits; found 1 cosmetic comment/derivation mismatch; flagged silent-zero-division + wadPow integer-inexactness footguns |

## Approach

1. **Scope selection with a trust model.** Before reading code, map the actors
   (owner/admin/spender/attacker), what each can do, and where the real external
   attack surface is — so effort goes to the paths that matter, not the whole tree.
2. **Line-cited reasoning.** Every observation references the exact function and
   line. Verdicts are derived from code structure + protocol/EVM/CosmWasm execution
   semantics (atomicity, checks-effects-interactions, hash-commitment relationships),
   not from vibes.
3. **Definitive severity, honestly.** Each candidate path ends in a clear verdict:
   *vulnerability*, *not a vulnerability* (with the invariant that protects it), or
   *needs PoC* (explicitly flagged as unproven). Low-confidence suspicions are never
   dressed up as findings.
4. **Turn robustness findings into contributions.** When a review surfaces
   non-exploitable robustness issues (e.g. a panic path, a missing validation), the
   fix is offered upstream as a reviewed PR rather than reported as a "bug."

## Why this exists

The bottleneck in open-source and onchain code has shifted from *writing* code to
*trusting* code — knowing whether a change is safe to merge. As AI-generated
contributions scale, the scarce skill is credible, auditable verification. These
reviews are a track record of exactly that: rigorous analysis with an honest
verdict, whether the verdict is "here is the bug" or "there is no bug here."

## Engagement

Available for **smart-contract security review work** — Solidity and CosmWasm-Rust.
Typical engagements: a focused review of a specific contract or module, a
second-opinion review before a deploy, or hardening a change before merge.

- **Contact / commission:** open a GitHub issue on this repo, or reach the profile
  linked from the reviews.
- **Payment:** USDC on **Base** — `0x48B76832F99D654Cc9A3Ef8897AE13125386DEF3`.
  Payment is only for work explicitly agreed and delivered; this address is a
  receiving rail, not a claim of any prior reward.

---

_All reviews are of public code, conducted read-only. No live contracts, websites,
or third-party infrastructure were interacted with. Reviews are informational and
not a warranty of security._
