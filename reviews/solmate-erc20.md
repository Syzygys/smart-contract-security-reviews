# Security Review — Solmate ERC20

**Target:** [transmissions11/solmate](https://github.com/transmissions11/solmate/blob/34d20fc027fe8d50da71428687024a29dc01748b/src/tokens/ERC20.sol) — `ERC20` (Solidity ≥0.8.0, AGPL-3.0), pinned at commit `34d20fc` ("New custodian", 2022-07-19, last commit to touch this file)
**Type:** Gas-optimized ERC-20 + EIP-2612 (`permit`) base contract, meant to be inherited
**Method:** Static, line-by-line review of the pinned raw source (206 lines — the entire file)
**Outcome:** **No vulnerability in the contract.** Balance/allowance bookkeeping, the
`unchecked` arithmetic, and the EIP-2612 signature/domain-separator logic are all
correct under the invariants the contract actually maintains. The real risk surface
is what Solmate deliberately omits relative to OpenZeppelin's ERC20 — documented
below as concrete integrator obligations, not library bugs.

## What it does

An `abstract contract` meant to be inherited (not deployed standalone): standard
`transfer`/`transferFrom`/`approve` (lines 68–110), EIP-2612 `permit` with cached
domain separator (lines 116–177), and internal `_mint`/`_burn` for subclasses to
expose (lines 183–205). No access control, no pausability, no hooks — those are
explicitly the inheriting contract's job.

## Transfer / allowance logic — correct

```solidity
function transferFrom(address from, address to, uint256 amount) public virtual returns (bool) {
    uint256 allowed = allowance[from][msg.sender];
    if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
    balanceOf[from] -= amount;
    unchecked { balanceOf[to] += amount; }
    ...
}
```

- **Infinite-approval optimization** (line 97): `allowance == type(uint256).max` is
  treated as "don't decrement" — the standard gas-saving convention used by USDT,
  Uniswap, and OZ's own `ERC20` for `type(uint256).max` approvals. Consistent with
  spec expectations (an infinite approval never needs bookkeeping). ✔
- **Debit is checked, credit is `unchecked`.** `balanceOf[from] -= amount` (line 99)
  and `allowance[...] -= amount` (line 97) use Solidity 0.8's default checked
  arithmetic, so an insufficient balance or allowance reverts rather than
  underflowing. The `unchecked { balanceOf[to] += amount; }` that follows is safe
  **only because of an invariant the contract itself maintains**: `sum(balanceOf) ==
  totalSupply` at all times, established by `_mint`'s checked `totalSupply += amount`
  (line 184) and preserved by `transfer`/`transferFrom` (debit and credit always sum
  to the same total). Since `totalSupply` itself fits in `uint256` by construction
  (mint reverts on overflow), no individual `balanceOf` entry can ever exceed it, so
  the unchecked credit can never overflow. ✔ — This is exactly the invariant the
  contract's own top-of-file NatSpec warns about (line 7: *"Do not manually set
  balances without updating totalSupply"*) — a subclass that writes to `balanceOf`
  directly (e.g. a custom migration/airdrop path) breaks the invariant this safety
  argument depends on, silently re-opening unchecked-overflow risk. Worth flagging to
  any integrator who touches `balanceOf` outside `_mint`/`_burn`/`transfer*`.

**Verdict: correct, and the informal safety argument for the `unchecked` blocks
actually holds — verified above rather than taken on faith.**

## EIP-2612 `permit` — correct, including the two classic footguns

```solidity
function permit(address owner, address spender, uint256 value, uint256 deadline,
                 uint8 v, bytes32 r, bytes32 s) public virtual {
    require(deadline >= block.timestamp, "PERMIT_DEADLINE_EXPIRED");
    unchecked {
        address recoveredAddress = ecrecover(
            keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(),
                keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)))),
            v, r, s);
        require(recoveredAddress != address(0) && recoveredAddress == owner, "INVALID_SIGNER");
        allowance[recoveredAddress][spender] = value;
    }
    emit Approval(owner, spender, value);
}
```

1. **`ecrecover` zero-address footgun — closed.** `ecrecover` returns `address(0)` on
   a malformed/invalid signature instead of reverting. Line 154 explicitly checks
   `recoveredAddress != address(0)` before comparing to `owner`, so a caller cannot
   pass `v=0` garbage and have it "match" an `owner` of `address(0)` (which is
   unreachable anyway — no account controls that address). ✔
2. **Nonce consumption is atomic with verification, including on revert.**
   `nonces[owner]++` is a post-increment evaluated *while building the hash to
   verify*, i.e. before the `require` on line 154. It looks like the nonce is
   "spent" even on a failed signature — but because the whole `permit()` call is one
   EVM message, a `require` revert unwinds **every** state change made during that
   call, including the nonce write. So a failed permit never actually consumes a
   nonce; only a call that passes the signature check does. Verified by tracing
   EVM revert semantics, not assumed. ✔
3. **Signature malleability — present at the `ecrecover` level, but does not expand
   attacker capability.** For any valid `(v, r, s)`, the complementary
   `(v', r, n-s)` (secp256k1 order `n`) also recovers to the same address —
   `ecrecover` itself doesn't reject non-canonical `s` (unlike OZ's `ECDSA.sol`,
   which explicitly enforces `s <= n/2`). This matters when a signature's *hash* is
   used as a replay-prevention key; **it is not used that way here** — replay
   protection is the `nonces[owner]` counter, and both malleable variants sign the
   *same* `(owner, spender, value, nonce, deadline)` tuple, so submitting either one
   sets the identical allowance. Malleability therefore adds no attack beyond what
   front-running the original signature already allows (point 4). Flagging this
   explicitly because it is the first thing an auditor familiar with OZ's `ECDSA`
   checks for, and the reason it's fine here is not "checked", it's "irrelevant to
   this contract's design" — worth stating rather than leaving implicit.
4. **Domain-separator replay-across-fork protection — correct.** `INITIAL_CHAIN_ID`
   and `INITIAL_DOMAIN_SEPARATOR` are cached in the constructor (lines 60–61).
   `DOMAIN_SEPARATOR()` (line 163) recomputes from scratch whenever
   `block.chainid != INITIAL_CHAIN_ID`, so a signature signed pre-fork cannot be
   replayed post-fork on the other chain — the classic "domain separator baked in at
   deploy time, chain forks, signature now valid on both chains" bug class (the
   reason EIP-1344 `CHAINID` exists) does not apply here. Verified against the
   actual conditional, not just the presence of `block.chainid` in the hash. ✔

**Verdict: the signature-verification and replay-protection logic is correct.**

## Integrator footgun: `permit` front-running / griefing (not a library bug)

Anyone holding a valid `(owner, spender, value, deadline, v, r, s)` tuple — not just
`owner` — can submit it; `permit()` has no `msg.sender` restriction. This is
standard EIP-2612 design (that's the point of the feature), but it creates a
well-known integration hazard: a contract that does `permit(...); transferFrom(...);`
in one transaction, assuming its own `permit` call will succeed, can have that
`permit` front-run (by anyone copying the pending calldata) — the front-run
transaction consumes the nonce with the *same* approval terms, so no funds are
misdirected, but the victim's own transaction's `permit()` call now reverts with
`INVALID_SIGNER`-adjacent nonce mismatch, DoS-ing a naive "permit must succeed"
integration. **Mitigation is entirely on the integrator**: wrap the `permit()` call
in a way that tolerates it already being consumed (e.g. check `allowance[owner][spender]
>= value` first and skip the call), never assume atomicity of permit + spend.

## Integrator footgun: no `address(0)` guards (deliberate, unlike OpenZeppelin)

Neither `transfer`/`transferFrom` (destination) nor `_mint`/`_burn` (lines 183–205)
check for `address(0)`. Concretely:
- `transfer(address(0), amount)` succeeds — `balanceOf[address(0)]` silently
  accumulates. The `sum(balanceOf) == totalSupply` invariant still holds (so the
  unchecked-arithmetic safety argument above is unaffected), but the tokens are
  economically burned without `totalSupply` reflecting it — any downstream code
  that assumes `totalSupply` equals circulating/spendable supply is wrong.
- `_mint(address(0), amount)` is reachable if a subclass exposes it without its own
  check — tokens are minted directly into a permanently inaccessible balance.

OpenZeppelin's `ERC20._transfer`/`_mint`/`_burn` (already reviewed in
[openzeppelin-safeerc20.md](openzeppelin-safeerc20.md)'s ecosystem) revert on
`address(0)` for exactly this reason. Solmate's contract-level NatSpec ("Modern and
gas efficient") signals the tradeoff: these checks cost gas on every call and are
omitted by design, on the assumption that inheriting contracts add whatever
validation their use case needs. **This is not a vulnerability in the base
contract** — it has no way to know whether a given deployment wants to allow
burn-via-transfer — but it is the single most consequential difference from the
OZ implementation for anyone porting code between the two, and it is easy to miss
because both contracts satisfy the same external `IERC20` interface.

## Conclusion

Solmate's `ERC20` is **not vulnerable**: the checked/unchecked arithmetic split is
backed by a real invariant that this review traced end-to-end rather than assumed,
the EIP-2612 implementation correctly closes the `ecrecover`-zero-address and
cross-fork replay classes of bugs, and the signature-malleability question — the
first thing worth checking given this contract skips OZ's canonical-`s`
enforcement — resolves cleanly because malleability here can't change *what* gets
approved, only *whether* a stale copy of the same approval gets submitted twice.
The actionable output for an integrator is the two gaps that are invisible from the
interface alone: **`permit` has no atomicity guarantee against front-running**, and
**this contract has none of OpenZeppelin's `address(0)` guards** — both are
deliberate gas/flexibility tradeoffs of "gas efficient" Solmate versus "defensive by
default" OZ, and porting code between the two without accounting for them is the
realistic failure mode, not a bug in this file.
