# Security

AgentGate is unaudited research code. Do not deploy it with real funds.

- There is no owner, no upgrade path, and no global pause beyond the per-mandate `trip`.
- Tests run against `MockAccount`, not Safe.
- A valid agent signature is not sufficient to move funds, but the implementation has not had an external audit.
- If you believe you have found a defect, open an issue. Do not deploy a proof against a live treasury.
