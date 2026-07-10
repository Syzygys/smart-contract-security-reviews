# Security Review — OpenZeppelin ECDSA

**Target:** [OpenZeppelin/openzeppelin-contracts](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol) — `ECDSA` (v5.6.0, Solidity ^0.8.20, MIT)
**Type:** ECDSA signature recovery / verification library
**Method:** Static, line-by-line review of the pinned raw source (284 lines)
**Outcome:** **No vulnerability in the library.** Its two classic `ecrecover`
footguns — signature malleability and the `address(0)` return — are both correctly
neutralised. The real review value is a set of **integration footguns**, including
one genuine sharp edge: `parse()` performs *no* validation.

## The two `ecrecover` footguns — both handled correctly

`ecrecover` is a precompile with two well-known dangers. This library closes both in
the core `tryRecover(hash, v, r, s)`:

1. **Malleability (s upper-half order).** EIP-2 leaves `ecrecover` malleable:
   `(r, s, v)` and `(r, n−s, v′)` recover the same signer, so a signature is not
   unique. The library rejects the upper half:
   ```solidity
   if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
       return (address(0), RecoverError.InvalidSignatureS, s);
   }
   ```
   The constant is `secp256k1n/2`; requiring `s ≤ secp256k1n/2` enforces the
   canonical (low-s) form. ✔ Correct.

2. **The `address(0)` return.** `ecrecover` returns `address(0)` on invalid input.
   The historic bug is a caller doing `recovered == expectedSigner` where a crafted
   invalid signature yields `0`. The library couples `0` with an error and never
   returns a zero signer silently:
   ```solidity
   address signer = ecrecover(hash, v, r, s);
   if (signer == address(0)) return (address(0), RecoverError.InvalidSignature, bytes32(0));
   ```
   The NatSpec guarantees it: *"This will not return address(0) without also
   returning an error description."* `recover(...)` reverts via `_throwError`;
   `tryRecover(...)` returns the error tuple. ✔ Correct. Invalid `v` (not 27/28)
   flows through `ecrecover`→`0`→`InvalidSignature`, so it is covered too.

**Verdict: the recovery core is correct and non-malleable.**

## Integration footguns (the part a caller must not miss)

1. **`parse()` / `parseCalldata()` do NO validation.** They split a 64- or 65-byte
   signature into `(v, r, s)` in assembly and return `(0,0,0)` on a bad length —
   but they perform **no malleability check and no zero-address check**. The NatSpec
   says as much: *"Consider validating the result before use, or use
   {tryRecover}/{recover} which perform full validation."* **Using `parse()` then
   calling `ecrecover` directly re-opens both footguns closed above.** Integrators
   should route through `tryRecover`/`recover`, not `parse` + raw `ecrecover`.

2. **Malleability protection is NOT replay protection.** Low-s uniqueness only means
   a `(message, signer)` pair has one canonical signature; it does **not** stop the
   same valid signature being submitted twice. The library states it explicitly:
   *"Developers SHOULD NOT use signatures as unique identifiers; use hash
   invalidation or nonces for replay protection."* This is the single most common
   real-world ECDSA integration bug — the library correctly puts it on the caller.

3. **`hash` must be a real hash of caller-structured data.** Per the IMPORTANT note:
   *"it is possible to craft signatures that recover to arbitrary addresses for
   non-hashed data."* If an attacker controls the `hash` input, they can pick
   `(r, s, v)` and back into an address. Callers must hash a message whose structure
   they control (EIP-712 / `toEthSignedMessageHash`), never verify attacker-supplied
   raw `hash`.

4. **The 65-byte-only restriction is DEPRECATED.** `tryRecover(hash, bytes)` rejects
   64-byte ERC-2098 short signatures today, but the NatSpec flags this restriction
   as deprecated and *"will be removed in v6.0."* Code that relies on 2098-rejection
   as a security boundary (e.g. a length-based invariant) will silently change
   behaviour on upgrade. Note the separate `tryRecover(hash, r, vs)` overload and
   `parse` already accept 2098 form.

## Conclusion

`ECDSA` is **not vulnerable**: it correctly enforces low-s canonicalisation and
never emits a silent `address(0)` signer. The actionable review output is the
integration guidance — above all, **do not use `parse()` + raw `ecrecover`** (it
bypasses every protection this library adds), and **add nonce/hash-invalidation
replay protection yourself**, because signature validity ≠ signature freshness.
