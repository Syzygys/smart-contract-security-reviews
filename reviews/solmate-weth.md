# Security Review — Solmate WETH

**Target:** [transmissions11/solmate](https://github.com/transmissions11/solmate/blob/34d20fc027fe8d50da71428687024a29dc01748b/src/tokens/WETH.sol) — `WETH` (pinned commit `34d20fc`, 35 lines, AGPL-3.0-only)
**Type:** Wrapped-Ether custodian contract (ERC-20-wrapped native ETH, `deposit`/`withdraw`/`receive`)
**Method:** Static, line-by-line review of the pinned raw source, cross-checked
against the already-reviewed [SafeTransferLib](solmate-safetransferlib.md) (used for
the ETH payout) and [Solmate ERC20](solmate-erc20.md) (the inherited `_mint`/`_burn`,
both re-fetched at the same pinned commit to confirm the exact bytes this contract
actually compiles against)
**Outcome:** **No vulnerability found.** The contract is 17 lines of logic on top of
an inherited, previously-reviewed ERC-20 base. The withdraw path follows correct
checks-effects-interactions ordering, `_burn`'s checked subtraction enforces the
solvency invariant, and cross-checking `safeTransferETH` closes the read-only /
cross-function reentrancy questions this design normally raises. Real, verified
footguns are named below — none of them are exploitable by another user.

## The full contract

```solidity
contract WETH is ERC20("Wrapped Ether", "WETH", 18) {
    using SafeTransferLib for address;

    event Deposit(address indexed from, uint256 amount);

    event Withdrawal(address indexed to, uint256 amount);

    function deposit() public payable virtual {
        _mint(msg.sender, msg.value);

        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) public virtual {
        _burn(msg.sender, amount);

        emit Withdrawal(msg.sender, amount);

        msg.sender.safeTransferETH(amount);
    }

    receive() external payable virtual {
        deposit();
    }
}
```

## Trust model

- **Actors:** any EOA or contract that calls `deposit`/sends plain ETH, and any
  holder of the resulting WETH balance who later calls `withdraw`. There is no
  owner, admin, pauser, or privileged role anywhere in this file — it is a fully
  permissionless, symmetric wrap/unwrap custodian by construction.
- **What an attacker can do:** call any function with arbitrary `amount`/`msg.value`,
  and — since `safeTransferETH` forwards `gas()` (all remaining gas, verified in the
  prior SafeTransferLib review) — execute arbitrary code inside `receive()`/`fallback()`
  during the ETH payout in `withdraw`, including calling back into this same WETH
  contract or any other contract.
- **The invariant that matters:** the contract's ETH balance must always be able to
  cover `totalSupply` — i.e. no sequence of calls should let anyone burn WETH they
  don't own, or withdraw more ETH than their burn produced.

## `deposit()` — correct, no external interaction

- L1: `payable`, so any `msg.value` is accepted.
- L2: `_mint(msg.sender, msg.value)` — re-fetched from `ERC20.sol` at the same
  pinned commit (L183-193): `totalSupply += amount` (checked, since pragma is
  `>=0.8.0` and this line is outside any `unchecked` block) then
  `balanceOf[to] += amount` inside `unchecked { }`, justified by the comment "cannot
  overflow because the sum of all user balances can't exceed the max uint256 value."
  For WETH specifically this bound is even tighter — `msg.value` is native ETH, whose
  total circulating supply is astronomically below `2**256`, so overflow here is not
  reachable by any real transaction.
- No external call is made in this function — `_mint` only writes storage and emits
  an event. **No reentrancy surface exists in `deposit()` at all.**

## `withdraw(amount)` — correct checks-effects-interactions ordering

1. **L1: `_burn(msg.sender, amount)` first.** Re-fetched `_burn` (`ERC20.sol`
   L195-205): `balanceOf[from] -= amount` is a **checked** subtraction (not inside
   `unchecked`) — if `amount > balanceOf[msg.sender]`, this line reverts with a
   Panic(0x11) before any further code in `withdraw` runs. This is the solvency
   check: you cannot burn (and therefore cannot later claim ETH for) more WETH than
   you hold. Only `totalSupply -= amount` is `unchecked`, justified by "a user's
   balance will never be larger than the total supply" — true as an invariant of
   `_mint`/`_burn` being the only two functions that touch `totalSupply`, both
   re-verified here.
2. **L2: event emitted** (no side effect on contract state or control flow).
3. **L3: `msg.sender.safeTransferETH(amount)` last.** Re-fetched
   `SafeTransferLib.safeTransferETH` (L15-24): raw `call(gas(), to, amount, 0, 0, 0, 0)`
   in assembly, `require(success, "ETH_TRANSFER_FAILED")` afterward. This is the
   external interaction, and by this point `balanceOf[msg.sender]` and `totalSupply`
   have **already** been decremented.

**Reentrancy analysis, traced explicitly:** because `_burn` (state change) happens
strictly before `safeTransferETH` (external call), a reentrant call into `withdraw`
from inside the recipient's `receive()`/`fallback()` — triggered during step 3 — sees
`balanceOf[msg.sender]` already reduced by the first call's `amount`. The reentrant
call can only burn and withdraw against what's left, which is exactly the caller's
real remaining balance; it cannot re-burn or re-claim the same tokens twice. This is
the standard CEI mitigation, and it is implemented correctly here — verified by
tracing the exact storage-write vs. external-call ordering in the fetched bytecode
source, not assumed from the pattern's name.

**Read-only reentrancy, checked and closed for this specific case:** a general
concern with ETH-forwarding `call` is that a reentrant callee might observe
inconsistent state (e.g. contract ETH balance already reduced by the `call`'s value
transfer, but application-level accounting not yet updated, or vice versa). Here the
EVM's `call` opcode transfers `amount` wei to `msg.sender` atomically as part of
executing the call — by the time the recipient's code runs, both (a) this contract's
ETH balance and (b) `totalSupply`/`balanceOf[msg.sender]` (updated in step 1, before
the call) have already moved together. There is no window in which a reentrant
observer sees stale WETH accounting alongside already-debited ETH, or the reverse.
No read-only reentrancy gap found in this contract's own logic.

## `receive()` — correct, minimal, no hidden fallback path

- Plain ETH sent with empty calldata routes to `receive()` (L1), which just calls
  `deposit()` (L2) — same accounting as an explicit `deposit()` call, verified above.
- There is **no `fallback()` function** in this file. A call that sends ETH *with*
  non-empty calldata that doesn't match `deposit()`/`withdraw(uint256)`'s selectors
  will revert entirely (no matching function, no fallback to catch it) rather than
  silently accepting ETH without minting WETH or silently discarding calldata. This
  is the safe failure mode — verified by the absence of a `fallback` declaration in
  the fetched source, not inferred.

## Conclusion

`WETH` is **not vulnerable**: `deposit()` has no external-call surface at all,
`withdraw()` burns before it pays out (checked subtraction enforcing solvency, then
an all-gas external call), and the ETH-value transfer and the WETH accounting update
move atomically together from any reentrant observer's point of view — closing both
the classic double-withdraw reentrancy and the read-only reentrancy question for this
specific contract. Two real, code-verified footguns for anyone building on or forking
this file, neither exploitable by one user against another:

1. **`deposit`, `withdraw`, and `receive` are all `virtual`.** Same class of risk
   already flagged in the [Solmate ReentrancyGuard review](solmate-reentrancyguard.md):
   a derived contract can `override` any of these three and the compiler enforces
   nothing about what the override actually does. An override that mints without
   requiring `msg.value`, or that skips `_burn` before paying out, would break the
   ETH-backing invariant entirely — but that is a risk introduced by whoever forks
   and overrides this contract, not a flaw in the base file as written.
2. **Force-fed ETH is permanently unclaimable, by design, not accounted for.** Any
   ETH that reaches this contract's balance without going through `deposit()`/
   `receive()` — e.g. via `selfdestruct(address(this))` from another contract, or as
   a `block.coinbase` mining/validator reward — increases `address(this).balance`
   without increasing `totalSupply`. No function in this file reads or exposes the
   surplus, and no holder's `withdraw()` call is affected (each `withdraw` only ever
   moves `amount` matched to that caller's own burned balance). This is a real value
   lock for whoever force-feeds the contract, not a way to steal already-wrapped
   ETH from other holders — but it is worth stating explicitly since it's the kind
   of "the numbers don't add up" observation an integrator doing balance
   reconciliation against `totalSupply` should expect and not mistake for a bug.
