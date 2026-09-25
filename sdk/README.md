# AgentGate SDK

TypeScript helpers for the hashes in `src/AgentGate.sol`.

- Scope, attestor, and guardian leaves use the OpenZeppelin double-hash.
- Merkle pairs are sorted and hashed with `keccak256(abi.encode(a, b))`.
- Proposal, attestation, ready, and co-sign hashes use the gate EIP-712 domain
  (`SMP-AgentGate`, version `1`).
- Two policies: vendor payments, and a DEX rebalance with a minimum-inflow floor.
- `reviewInFlight` returns `withdrawAttestation` calldata when a counted attestor's
  ticket no longer matches the policy. It does not send a transaction.

```
npm test
```

`test/sdk.test.ts` checks the hashes against `test/fixtures/vectors.json`. That file is
written by `SdkVectorsTest` in the Solidity suite. If you change an encoding, run
`forge test --match-contract SdkVectorsTest` and then `npm test`.

This SDK does not deploy a Safe and does not hold a key for a public testnet.