# Security Review — Injective swap-contract

**Target:** [InjectiveLabs/swap-contract](https://github.com/InjectiveLabs/swap-contract) (CosmWasm, Rust)
**Type:** DEX swap router over Injective's exchange module
**Method:** Static review + upstream code-hardening contribution
**Outcome:** **No exploitable vulnerability.** Two non-exploitable robustness issues
found and turned into a reviewed pull request to the upstream repository.
**Contribution:** [InjectiveLabs/swap-contract#23](https://github.com/InjectiveLabs/swap-contract/pull/23)
— *Fix panics in reply parsing + validate route continuity*.

## What was reviewed

The contract routes a swap across one or more Injective exchange markets, using
CosmWasm submessages and `reply` handling to read execution results. Four candidate
paths were examined; the trust model is central to every verdict:

- `set_route` / `verify_route_exists` is **admin-only** — not an external attack
  surface.
- CosmWasm execution is atomic: a panic or trap rolls back the entire transaction;
  `reply_on_success` callbacks are strictly serial within a single transaction.

## Finding 1 — `parse_market_order_response()` panic path → Low/Info (not exploitable)

The reply parser used `.unwrap()` on the submessage response, which can panic. Root
cause was a type mismatch, not a missing check: the return type was `StdResult`
(which only carries `StdError`), while the author had already defined
`ContractError::SubMsgFailure` / `ReplyParseFailure` variants that could not be
propagated through it — forcing the `.unwrap()`. An empty `msg_responses` also led
to an implicit `Option::unwrap()` panic.

**Severity reasoning:** CosmWasm panic/trap semantics roll the whole transaction
back atomically. The worst case is "this swap fails," not fund loss or state
corruption. **Low/Info — not a reportable vulnerability.**

**Contribution:** changed the return type to `Result<_, ContractError>` so the
already-defined error variants propagate via `?`, and added explicit handling for an
empty `msg_responses` — removing the panic paths without changing behaviour on the
success path.

## Finding 2 — `verify_route_exists()` missing continuity check → Low/Info (not exploitable)

`set_route` validated that the first market contains the source denom, the last
contains the target, and the route has no duplicates — but did not verify that
*adjacent* markets share a denom (route continuity).

**Severity reasoning:** `set_route` is admin-only, so this is not an external attack
surface; and even a misconfigured route fails safely — the downstream exchange
module rejects mismatched denoms and the whole transaction reverts. **Low/Info —
not a reportable vulnerability.**

**Contribution:** added an adjacency continuity check so a misconfigured route is
rejected at `set_route` time rather than failing later at swap execution.

## Findings 3 & 4 — examined and dismissed

- **exact-output buffer / rounding:** dismissed as *not a bug* on the project's own
  evidence — a test comment in the repo states the query "overestimates the amount…
  can execute the swap with less," confirming the bias direction is conservative and
  the excess is refunded. Authoritative first-party evidence, not speculation.
- **`SWAP_OPERATION_STATE` / `STEP_STATE` singleton state:** not a design flaw —
  CosmWasm `reply_on_success` callbacks are strictly serial within a transaction, so
  there is no concurrent-overwrite path. This is guaranteed by the execution model.

## Conclusion

Honest result: **no reportable vulnerability.** Three of the four paths are
low-severity robustness issues protected by the admin trust model or CosmWasm
atomicity; the fourth was disproven by the project's own test documentation. The two
robustness findings were valuable enough to contribute upstream as a reviewed PR
rather than reported as a "bug."

**Verification honesty:** `cargo check -p swap-contract --lib` and
`cargo clippy -p swap-contract --lib` were clean; the full `cargo test` suite could
not run locally (its `injective-test-tube` dev-dependency requires a Go toolchain not
present on the review machine). The PR description states this plainly and defers the
test suite to CI — no verification was claimed that was not actually performed.
