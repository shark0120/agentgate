# Audit readiness

Not audited. Do not deploy with real funds.

## Scope

In scope for a review of this repository:

- `src/AgentGate.sol`, `src/GateSettlement.sol`, `src/GateBase.sol`, `src/GateTypes.sol`, `src/GateErrors.sol`
- `src/libraries/GateChecks.sol`
- `src/verifiers/EcdsaAttestationVerifier.sol`
- `src/SafeAgentGateAdapter.sol`
- `sdk/` as the off-chain attestor and encoding library
- `SPEC.md` as the intended behavior

Out of scope:

- `archive/s0/`. It is the previous custodial prototype and is not compiled.
- The Safe contracts under `lib/safe-v1.4.1` and `lib/safe-v1.5.0`. They are upstream. Review the
  adapter's use of them, not Safe itself.
- A public deployment. There is none.

## Build the reviewer should use

- solc 0.8.30, `via_ir`, optimizer 200, Cancun, for AgentGate.
- Safe creation bytecode in `test/safe/bytecode/` is the tagged source compiled with the same solc,
  optimizer 200, Cancun, `via_ir` off. Safe v1.4.1 does not compile under this project's `via_ir`
  pipeline. Tests deploy that bytecode with `create`.

```
forge test
```

`sdk/` has its own test: `npm test` from that directory. It checks hashes against
`sdk/test/fixtures/vectors.json`, which `SdkVectorsTest` writes from Solidity.

## Properties the tests exercise

- Admission rejects A1-A17, execution rejects X1-X10, delegation rejects G1-G4, on `MockAccount`.
- One Foundry invariant: capability-tree budget conservation, measured USDC outflow equals recorded
  consumption, and one recipient inside a child scope but outside the root scope is never paid.
  That run is a single mandate with no epoch change. It is not a proof.
- Shrink does not refund USDC or native consumption (`MultiAssetTest`).
- On Safe v1.4.1 and v1.5.0: a USDC payment is measured on the Safe; ERC-1271 co-sign shortens the
  window; a raw owner signature of the gate hash does not; `enableModule`, `addOwnerWithThreshold`,
  `setGuard`, and `setFallbackHandler` each block execution and make `trip` succeed. v1.5.0 also
  covers `setModuleGuard`. The module list past the first page is part of the digest.

## Known issues

1. Adapter honesty. The gate trusts `account`, `configDigest`, and `agentAuthority`. A malicious
   adapter can report a calm digest and move funds elsewhere. The Safe adapter is the one the tests
   cover.
2. Owner path. Safe owners can transfer funds without the gate. T7 does not bind the owners.
3. Allowance enumeration. Only the call target, and the spender argument of `approve` /
   `increaseAllowance`, are checked. Other spenders are T6.
4. Proxy leaves. A leaf with `implementation != 0` is rejected. EIP-1967 checks are not in this version.
5. `stateRef` is limited to 256 blocks. EIP-2935 is not used.
6. A single counted attestor can stall a ticket by withdrawing. Rotation waits out the activation delay.
7. Fixed periods can spend up to twice the period cap across a boundary.
8. Calldata is public at admission. The window is also an exposure window.
9. No symbolic check has been run. Halmos is not part of this environment, and this document does
   not pretend otherwise.
10. No external audit. A report does not exist. Do not treat the test suite as one.

## What a reviewer should try to break

- A module, owner, guard, fallback handler, or module guard that changes the Safe without changing
  the digest the gate stored.
- An agent address that can execute on the Safe without `agentAuthority` returning true.
- A second call, or a `DELEGATECALL`, coming out of `executeFromGate`.
- A shrink that increases `capRemaining` above `newCap - consumed`.
- A ticket that settles after the epoch changes.
- An attestation whose `blob` verifies for a different proposal, policy, epoch, or expiry.
- The reference attestor signing a proposal its policy function rejects.