# AgentGate

Attestation-gated execution for AI agents. An agent's signature is a proposal, not a command. Funds stay in the account. Settlement happens only when six conditions hold at once.

**Not audited. Not deployed to a public network. Do not use with real funds.**

Safe integration is in `src/SafeAgentGateAdapter.sol`. Tests deploy Safe v1.4.1 and v1.5.0 creation bytecode built from the tagged source. The older suite still uses `MockAccount`. There is no external audit and no public testnet deployment.

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

- 146 tests passed, 0 failed, on 2026-09-26 with Foundry 1.8.3. That includes the previous MockAccount suite, Safe v1.4.1, Safe v1.5.0, and one invariant test.
- Invariant run: 128 runs, depth 128, 16,384 calls, 0 reverts, on one mandate with no epoch change.
- Properties checked: capability-tree budget conservation; measured USDC outflow equals recorded consumption; one fixture where a recipient is inside a child scope but outside the root scope, and is never paid. That fixture is not a general proof about every out-of-scope recipient.
- Safe tests show that `enableModule`, `addOwnerWithThreshold`, and `setGuard` each block execution and make `trip` succeed. v1.5.0 also covers `setModuleGuard`. Principal co-sign goes through Safe ERC-1271. A raw signature of the gate hash does not.
- Runtime size after batching the account check into `accountSnapshot`: AgentGate 21,390 bytes; GateSettlement 12,232 bytes. See `docs/GAS.md`.

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
| `src/AgentGate.sol` | Registry and admission. Runtime 21,390 bytes. |
| `src/GateSettlement.sol` | Execute, veto, cancel, release, delegation upkeep. Runtime 12,232 bytes. |
| `src/libraries/GateChecks.sol` | Stateless leaf, delegation, and shrink checks. Runtime 4,767 bytes. |
| `src/verifiers/EcdsaAttestationVerifier.sol` | ECDSA / ERC-1271 attestations. |
| `SPEC.md` | Merged specification. |
| `src/SafeAgentGateAdapter.sol` | Safe module. One CALL. DELEGATECALL refused. |
| `test/f1` | Reject-path and invariant tests. |
| `test/safe` | Safe v1.4.1 and v1.5.0. |
| `sdk/` | TypeScript scope trees, attestations, two policies, reference attestor. |
| `docs/` | Threat model, audit pack, gas notes. |
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
- The gate reads the account, the config digest, and other authority in one `accountSnapshot` call. `account`, `configDigest`, and `agentAuthority` remain and must match the snapshot.

## 中文

代理人的簽章只是提案。六件事同時成立才結算：範圍、世代、預算預留、獨立見證、等待窗、實測扣減。資產不進閘門。

```
forge test
```

Safe 接線在 `src/SafeAgentGateAdapter.sol`，測試打的是 v1.4.1 和 v1.5.0 的官方原始碼。還沒審計，也還沒部署到公開測試網，不能拿去管真的資金。規格見 [SPEC.md](SPEC.md)。威脅模型見 [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)。

## License

MIT. See [LICENSE](LICENSE).
