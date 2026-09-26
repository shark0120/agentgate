# Gas notes

Measured with Foundry 1.8.3, solc 0.8.30, `via_ir`, optimizer 200, on 2026-09-26.
MockAccount figures are one call each from `test_V1_legalAct_reservesThenDebitsMeasuredOutflow`.
Safe figures are one call each from `test_settlesUsdcFromTheSafe` on v1.4.1.
The account check is now one `accountSnapshot` call. Merkle proofs and signature checks were not rewritten. Reject codes are unchanged.

| Contract | Runtime size | Margin to 24,576 |
| --- | --- | --- |
| AgentGate | 21,390 bytes | 3,186 bytes |
| GateSettlement | 12,232 bytes | 12,344 bytes |

Before this change the same build reported AgentGate at 22,933 bytes and GateSettlement at 12,989 bytes.

| Call | MockAccount | Safe v1.4.1 |
| --- | --- | --- |
| activate | 189,406 | 221,574 |
| admit | 248,131 | 280,335 |
| execute, through the gate fallback | 173,444 | 209,378 |
| GateSettlement.execute | 126,731 | not isolated |

On that Safe test, `accountSnapshot` was 28,195 gas at its minimum. The previous unbatched `configDigest` minimum in a mixed report was 29,062, and that call did not include the authority check. The gate used to pay for three calls.

The previous combined report's highest admit was 289,445. That figure mixed MockAccount with both Safe versions, so it is not a paired before-and-after of one transaction.

No public deployment and no external audit are implied by these numbers.
