# Security Review — Solmate ERC721

**Target:** [transmissions11/solmate](https://github.com/transmissions11/solmate/blob/34d20fc027fe8d50da71428687024a29dc01748b/src/tokens/ERC721.sol) — `ERC721` (Solidity ≥0.8.0, AGPL-3.0), pinned at commit `34d20fc` ("New custodian", 2022-07-19, last commit to touch this file)
**Type:** Gas-optimized ERC-721 base contract, meant to be inherited
**Method:** Static, line-by-line review of the pinned raw source (231 lines — the entire file, including the paired `ERC721TokenReceiver` contract)
**Outcome:** **No vulnerability in the contract.** Ownership/approval bookkeeping is
correct, the `unchecked` balance counters are backed by invariants this review
traced end-to-end, and `safeTransferFrom`/`_safeMint` follow checks-effects-
interactions correctly despite the external callback. The one behavior worth a
hard caveat — the `to.code.length == 0` receiver-check bypass during a
recipient's own constructor — is a known, real footgun, documented below with the
exact mechanism rather than asserted.

## What it does

An `abstract contract` meant to be inherited (not deployed standalone): single-
token `approve`/operator `setApprovalForAll` (lines 66–80), `transferFrom` and its
two `safeTransferFrom` overloads (lines 82–140), ERC165 `supportsInterface`
(lines 146–151), and internal `_mint`/`_burn`/`_safeMint` for subclasses to expose
(lines 157–217). No access control on mint/burn, no enumerable extension, no
transfer hooks — all left to the inheriting contract, consistent with Solmate's
"gas efficient, minimal" design across the library (already established for
[`ERC20`](solmate-erc20.md) and [`MerkleProofLib`](solmate-merkleprooflib.md)).

## `transferFrom` — authorization and bookkeeping, correct

```solidity
function transferFrom(address from, address to, uint256 id) public virtual {
    require(from == _ownerOf[id], "WRONG_FROM");
    require(to != address(0), "INVALID_RECIPIENT");
    require(
        msg.sender == from || isApprovedForAll[from][msg.sender] || msg.sender == getApproved[id],
        "NOT_AUTHORIZED"
    );
    unchecked {
        _balanceOf[from]--;
        _balanceOf[to]++;
    }
    _ownerOf[id] = to;
    delete getApproved[id];
    emit Transfer(from, to, id);
}
```

- **Three-way authorization (line 91–94) is complete and correctly scoped**: the
  owner themself, a blanket operator (`isApprovedForAll`), or the single address
  approved for *this specific* `id` (`getApproved[id]`). No other path reaches the
  balance/owner mutation. ✔
- **`WRONG_FROM` (line 87) doubles as the existence check.** There is no separate
  `_exists(id)` helper (unlike OpenZeppelin). For an unminted `id`, `_ownerOf[id]`
  is `address(0)`, so this line only passes if the caller supplied `from ==
  address(0)`. Reaching the following `NOT_AUTHORIZED` check would then require
  `msg.sender == address(0)` (or `isApprovedForAll[address(0)][msg.sender]`,
  which can never be set — `setApprovalForAll` only ever writes under
  `isApprovedForAll[msg.sender][...]`, and no code path lets `msg.sender` be
  `address(0)` in the first place, since every call frame's sender is either a
  signed EOA or a live contract, both non-zero). So `transferFrom` on a
  never-minted token is unreachable past `WRONG_FROM`, not merely "checked
  elsewhere" — traced, not assumed. ✔
- **Unchecked balance decrement/increment (lines 98–102) is safe under the
  invariant `_ownerOf[id] == from` holding at that point** (just established by
  line 87): `from` owns at least this one token, so `_balanceOf[from] >= 1`,
  making the decrement's underflow impossible; the increment can't realistically
  overflow a `uint256` counter (same argument as `_mint`, below). This is the
  exact class of "informal unchecked comment" this review verifies rather than
  takes on faith — it holds. ✔
- **Approval is cleared on every transfer** (`delete getApproved[id]`, line 106)
  — a single-token approval never survives past the transfer it authorized, so a
  re-minted `id` (after a `_burn`) cannot inherit a stale approval from a
  previous life of that token id (`_burn` also deletes `getApproved[id]`, line
  184). Verified both paths clear it, not just the common one. ✔

**Verdict: correct.**

## `safeTransferFrom` / `_safeMint` — checks-effects-interactions, correct

```solidity
function safeTransferFrom(address from, address to, uint256 id) public virtual {
    transferFrom(from, to, id);
    require(
        to.code.length == 0 ||
            ERC721TokenReceiver(to).onERC721Received(msg.sender, from, id, "") ==
            ERC721TokenReceiver.onERC721Received.selector,
        "UNSAFE_RECIPIENT"
    );
}
```

- **State is fully committed before the external call.** `transferFrom` (line
  116) runs to completion — owner, balances, and approval are all updated and
  the `Transfer` event is emitted — *before* `onERC721Received` is invoked on
  `to`. If the receiver's callback reenters (e.g. calls `transferFrom` again on
  the same `id`), it does so against already-correct state: `to` is genuinely
  the on-chain owner by that point, so any further transfer it triggers is a
  legitimate action by the new owner, not a state-confusion exploit. Standard
  CEI, correctly applied despite the external call sitting in the middle of a
  "single logical operation." ✔
- **Revert-on-mismatch is atomic with the transfer.** Because `safeTransferFrom`
  makes no state changes of its own after `transferFrom` returns, a failed or
  wrong-selector callback (`require` on lines 118–123) reverts the *entire*
  transaction, unwinding the ownership change too — there is no window where the
  transfer "sticks" despite the safety check failing. ✔
- **Non-contract recipients skip the call entirely** (`to.code.length == 0`,
  line 119) — correct and required behavior, since calling a function that
  doesn't exist on an EOA is meaningless; this is the standard, spec-compliant
  way every mainstream ERC721 implementation (including OZ) detects "is this a
  contract."

**Verdict: correct — no reentrancy vulnerability, and the safety check is
genuinely atomic with the transfer it guards.**

## Integrator footgun: `code.length == 0` bypass during the recipient's own constructor

This is the one behavior in the file that a naive user of `safeTransferFrom`
could be surprised by, and it is real, not hypothetical:

`to.code.length` reads the recipient's *currently deployed* bytecode size. A
contract executing inside its own constructor has no deployed code yet — its
`EXTCODESIZE` is `0` until the constructor returns and the runtime code is
stored. Concretely: if contract `F`'s constructor does
`nft.safeTransferFrom(alice, address(this), id)` (e.g. a factory that mints
itself an NFT during deployment, or any pattern where a not-yet-fully-
initialized contract receives a token mid-construction), `to.code.length == 0`
evaluates `true` for that call, `onERC721Received` is **never invoked**, and the
transfer succeeds unconditionally — exactly as if `to` were an EOA. If `F`
never actually implements `onERC721Received` (because its author assumed the
"safe" transfer would have caught that), the NFT is now owned by a contract that
cannot pass it on via any *other* protocol's `safeTransferFrom` check (since by
then `F` has code, and if it lacks the interface, those later transfers to `F`
would correctly fail — the risk is the *asymmetry*: this specific mint/transfer
during construction slips through when a later one to the same, now-deployed
address would not). This is inherent to using `EXTCODESIZE` as the "is a
contract" oracle rather than a genuine capability check, and it affects every
ERC721 implementation using this pattern (OpenZeppelin's `Address.isContract`
carries the identical caveat, verified in [openzeppelin-address.md](openzeppelin-address.md)) — it is **not unique to Solmate**, but it is easy to
miss precisely because `safeTransferFrom`'s whole purpose is "guarantee the
receiver can handle this," and this is the one path where that guarantee
silently does not hold.

## Integrator footgun: single-token `approve` is a race, same class as ERC-20's

`approve(spender, id)` (line 66) unconditionally overwrites `getApproved[id]`
for whoever is authorized to call it — there is no "reset to zero first" dance
(unlike some ERC-20 mitigations for the analogous allowance-race). If an owner
changes their mind and calls `approve(B, id)` to replace an earlier
`approve(A, id)`, `A` can front-run the replacement transaction and call
`transferFrom` first, using the still-valid old approval. This is the standard,
well-known approve-front-running pattern that applies to any single-slot
approval primitive (ERC-20 allowances, this contract's `getApproved`) — it is a
property of the approval model itself, not a bug introduced by this
implementation, and no ERC721 in wide use (including OpenZeppelin's) closes it
differently. Documented because it is the first thing worth checking given how
much of this review's ERC-20 companion piece was about exactly this class of
issue, and the answer here is the same: **revoke by setting a fresh approval
only when you trust the previous approvee not to race you, or don't rely on a
mid-flight approval swap being atomic.**

## `_mint` / `_burn` — invariant-preserving, correct

```solidity
function _mint(address to, uint256 id) internal virtual {
    require(to != address(0), "INVALID_RECIPIENT");
    require(_ownerOf[id] == address(0), "ALREADY_MINTED");
    unchecked { _balanceOf[to]++; }
    _ownerOf[id] = to;
    emit Transfer(address(0), to, id);
}

function _burn(uint256 id) internal virtual {
    address owner = _ownerOf[id];
    require(owner != address(0), "NOT_MINTED");
    unchecked { _balanceOf[owner]--; }
    delete _ownerOf[id];
    delete getApproved[id];
    emit Transfer(owner, address(0), id);
}
```

- **`ALREADY_MINTED` (line 160) prevents overwriting an existing owner** —
  minting the same `id` twice is impossible without an intervening `_burn`, so
  ownership records can't be silently clobbered. ✔
- **`_burn`'s unchecked decrement (line 179) is safe under the same-line
  invariant**: `owner != address(0)` (just checked) means this `id` currently
  contributes exactly 1 to `_balanceOf[owner]`, so the decrement cannot
  underflow. Both `getApproved[id]` and `_ownerOf[id]` are cleared, so a
  subsequent `_mint` of the same `id` starts from a genuinely clean slate — no
  approval or ownership residue from the token's previous life. Verified by
  reading both functions together, not each in isolation. ✔
- **`_balanceOf[to]++` overflow (line 164) requires `2^256` mints to a single
  address** — gas cost alone makes this economically impossible on any real
  chain; the NatSpec comment's claim ("incredibly unrealistic") is accurate, not
  hand-waved. ✔

**Verdict: correct.**

## `approve` / `ownerOf` / `balanceOf` — no exploitable edge case

- `approve` (line 66) reads `_ownerOf[id]` without an existence check, but as
  argued under `transferFrom` above, an unminted `id` makes `owner ==
  address(0)`, and the following `require(msg.sender == owner || ...)` is then
  unreachable for any real caller — the same "no code path sets `msg.sender ==
  address(0)`" argument applies identically here. Not exploitable.
- `ownerOf`/`balanceOf` (lines 35–43) are `view` functions with straightforward
  `require` guards (`NOT_MINTED`/`ZERO_ADDRESS`); no state mutation, no
  reentrancy surface.
- `supportsInterface` (lines 146–151) returns the correct, standard selectors
  for ERC165 (`0x01ffc9a7`), ERC721 (`0x80ac58cd`), and ERC721Metadata
  (`0x5b5e139f`) — checked against the EIP text, not copied on faith.

## Conclusion

Solmate's `ERC721` is **not vulnerable**: the three-way transfer authorization
is complete, every `unchecked` block is backed by an invariant this review
re-derived rather than accepted from the inline comment, approvals are cleared
on both `transferFrom` and `_burn` so no re-minted token can inherit stale
state, and `safeTransferFrom`/`_safeMint` apply checks-effects-interactions
correctly — the callback happens strictly after state commit, closing the
reentrancy class that pattern is designed to guard against. The two things
worth an integrator's attention are not bugs but properties of the design: the
`EXTCODESIZE`-based receiver check is blind to a contract still inside its own
constructor (a real, if narrow, way to silently skip the "safe" guarantee), and
single-slot `approve` carries the same front-running race every allowance-style
primitive does. Neither is specific to this implementation, and both are named
here precisely because they are invisible from the external interface alone.
