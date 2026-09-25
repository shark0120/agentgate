# AgentGate

Attestation-gated execution for AI agents. An agent's signature is a proposal, not a command. Funds stay in the account. Settlement happens only when six conditions hold at once.

**Not audited. Not deployed. Do not use with real funds.** Tests run against `MockAccount`, not a Safe. Safe integration is the next milestone.

## The six conditions

1. The action matches a leaf in the committed scope tree, including every ancestor.
2. The mandate epoch is still current.
3. Budget can be reserved at admission, per asset, per node, and per period.
4. A threshold of attestors, bound to a committed set, signs that the action matches a policy text. The agent cannot attest for itself.
5. A veto window elapses with no veto and no withdrawn attestation. The window scales with the amount at risk and restarts after a sequencer outage.
6. Measured balance and allowance changes do not exceed the declared bounds. Budget is debited by the measured outflow.

The worst case the protocol aims to bound is the budget that can be reserved inside one veto window. That bound depends on the account adapter actually being the agent key's only path.

## Status

Verified locally on 2026-09-26 with Foundry 1.8.3, solc 0.8.30, OpenZeppelin Contracts 5.7.0, `via_ir`, Cancun:

- 103 tests passed, 0 failed (102 unit tests and 1 invariant test).
- Invariant run: 128 runs, depth 128, 16,384 calls, 0 reverts, on one mandate with no epoch change.
- Properties checked: capability-tree budget conservation; measured USDC outflow equals recorded consumption; one fixture where a recipient is inside a child scope but outside the root scope, and is never paid. That fixture is not a general proof about every out-of-scope recipient.
- Runtime size: AgentGate 21,204 bytes; GateSettlement 12,186 bytes; GateChecks 4,767 bytes.

The gate has no owner, no upgrade path, and no global switch. `GateSettlement` is reached by `DELEGATECALL` through an extension address fixed at construction. Calling the extension directly is rejected.

## Build

```
forge test
```

`forge` may live in `~/.foundry/bin` and not on `PATH`.

Dependencies are vendored under `lib/` (forge-std and OpenZeppelin Contracts 5.7.0) and keep their own licenses.

## Layout

| Path | Role |
| --- | --- |
| `src/AgentGate.sol` | Registry and admission. Runtime 21,204 bytes. |
| `src/GateSettlement.sol` | Execute, veto, cancel, release, delegation upkeep. Runtime 12,186 bytes. |
| `src/libraries/GateChecks.sol` | Stateless leaf, delegation, and shrink checks. Runtime 4,767 bytes. |
| `src/verifiers/EcdsaAttestationVerifier.sol` | ECDSA / ERC-1271 attestations. |
| `SPEC.md` | Merged specification. |
| `test/f1` | Reject-path and invariant tests. |
| `archive/s0` | Previous custodial prototype. Not compiled. |

## Specification

`SPEC.md` merges two designs and records twelve corrections to the source protocol (F-1 through F-12). One example: shrinking a mandate must not refund consumption.

The protocol backbone is attributed to @川, 2026-09-25. See SPEC.md §0.

## Implementation notes

- A child capability id is derived from `(mandateId, nonce)`. Deriving it from the proposal hash would cycle, because the child preimage is inside the calldata covered by that hash.
- A tampered ticket preimage is reported as `X3_NoTicket`. The altered hash does not find a record, so the check never reaches X1.
- Allowlists are extra leaves, not an `IN_SET` parameter rule. The scope tree is the set.
- Tests read time with `vm.getBlockTimestamp()`. Under `via_ir`, `block.timestamp` in the same call frame can stay stale after `vm.warp`.
- `mandateId` is first come, first served. Anyone can register an id. That only affects that id; the principal picks another.

## 中文

代理人的簽章只是提案。六件事同時成立才結算：範圍、世代、預算預留、獨立見證、等待窗、實測扣減。資產不進閘門。

```
forge test
```

目前接的是 `MockAccount`，不是 Safe。還沒審計，不能拿去管真的資金。規格見 [SPEC.md](SPEC.md)。前一版 S0 封存在 [archive/s0](archive/s0/README.md)，不參與編譯。

## License

MIT. See [LICENSE](LICENSE).
