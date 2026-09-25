# Threat model

This document names the assumptions the implementation actually relies on. It is not an audit.
T1-T11 are the assumptions in SPEC.md section 11. The reaction to a broken assumption is refusal
or suspension. There is no admin key that can force a settlement.

## Assets and trust boundaries

Funds stay in the principal account. The gate stores counters, not tokens. The only way the gate
moves funds is `IAccountAdapter.executeFromGate`, which `SafeAgentGateAdapter` implements as one
`CALL` through `execTransactionFromModule`. The adapter refuses `DELEGATECALL`.

The principal names both the account and the adapter in `MandateCommit`. The gate rejects a commit
whose adapter reports a different account. That check is only as honest as the adapter. A malicious
adapter can lie. Installing `SafeAgentGateAdapter` and disabling every other module is the principal's
job. The owner of a Safe can always act outside the gate. T7 is about the agent key, not the owner.

## Assumptions

| Id | Assumption | If it fails | What the code does |
| --- | --- | --- | --- |
| T1 | The sequencer stays live long enough for a veto | A veto may miss the window | `execute` reverts while `ILivenessSource.isUp` is false. A liveness change restarts the window plus `outageGrace` |
| T2 | The host chain does not rewrite the gate | Rules can change under the principal | Residual. The gate has no owner and no upgrade path. Pick a host whose upgrade delay is longer than the mandate |
| T3 | Fewer than the attestation threshold collude with the agent | A bad action can be admitted | Guardians and the principal can veto during the window. `trip` and `suspend` bump the epoch and kill in-flight tickets |
| T4 | Attestors answer | Nothing settles | Admission reverts. The principal still acts through the account directly |
| T5 | The agent key is not stolen | Someone else can propose | A stolen key still needs scope, budget, attestations, the window, and measured settlement |
| T6 | The target behaves like the leaf says | Measurement can miss an effect | Code-hash drift is X5. Anyone can `trip` on it. Allowance checks cover the call target and `approve` / `increaseAllowance` spenders only |
| T7 | The gate is the agent key's only path | The budget is not a loss bound | Commit and execute read `configDigest` and `agentAuthority`. A digest mismatch is A15 or X6. Anyone can `trip` |
| T8 | An oracle is honest | A cross-asset cap could be wrong | Not used. F1 has no oracle and no aggregate cap |
| T9 | Attestors have the policy text that matches `policyHash` | They cannot review | They do not sign. Admission fails closed |
| T10 | Time moves forward | Windows and expiry are meaningless | F1 uses `block.timestamp` only |
| T11 | This deployment is not upgraded | A later admin could change the rules | No owner, no proxy admin, settlement extension fixed at construction |

## What a Safe digest covers

`SafeAgentGateAdapter.configDigest` hashes owners, threshold, every enabled module, the guard slot,
the fallback-handler slot, and the module-guard slot. v1.4.1 has no module guard; that word is zero.
The list is paginated. If it cannot be read in full, the adapter reverts. A truncated list would hide
a module, so truncation is a failure, not a success.

`agentAuthority(agent)` is true when that address is an owner or an enabled module. The gate then
refuses the commit. The adapter itself is a module. It must not be the agent.

## Loss bound

The bound the protocol aims for is the budget that can be reserved inside one veto window, and only
while T7 holds. Tests show that bound on `MockAccount` and, for the configuration changes below, on
Safe v1.4.1 and v1.5.0. They do not show it for an account whose adapter lies, or for a Safe whose
owners keep another module enabled.

## Explicit non-goals

- No claim that a signature is enough to pay.
- No claim of an external audit.
- No claim that the vendored Safe bytecode equals the canonical mainnet singleton. It is the tagged
  source, compiled with solc 0.8.30, optimizer 200, `via_ir` off. See `test/safe/bytecode/README.md`.
- No claim that Halmos or another symbolic checker has been run.