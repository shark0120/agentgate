# Gas notes

Measured with Foundry 1.8.3, solc 0.8.30, `via_ir`, optimizer 200, on the happy-path
test `test_V1_legalAct_reservesThenDebitsMeasuredOutflow` against `MockAccount`.
One call each. This is a measurement, not a claim that admission has been micro-optimized.
The cost is the account reads, the Merkle proofs, and the signature checks. Changing those
to save gas would risk the reject table, so they were left alone.

| Contract | Runtime size |
| --- | --- |
| AgentGate | 22,933 bytes |
| GateSettlement | 12,989 bytes |

EIP-170 limit is 24,576 bytes. AgentGate is under it after the adapter field was added.

| Call | Gas |
| --- | --- |
| activate | 190,645 |
| admit | 249,410 |
| execute, through the gate fallback | 174,676 |
| GateSettlement.execute | 127,939 |

Safe settlement is a separate path. `test_settlesUsdcFromTheSafe` costs about 1.18 million gas
for the whole test, including deployment of the Safe stack in `setUp`. That number is not the
marginal cost of one payment.

No further admission optimization is claimed.