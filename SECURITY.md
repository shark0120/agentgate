# Security

AgentGate is unaudited research code. Do not deploy it with real funds.

- There is no owner, no upgrade path, and no global pause beyond the per-mandate `trip`.
- `SafeAgentGateAdapter` is tested against Safe v1.4.1 and v1.5.0 creation bytecode built from the tagged source. That bytecode is not the canonical mainnet singleton.
- The older unit suite still uses `MockAccount`.
- A valid agent signature is not sufficient to move funds. There has been no external audit.
- If you believe you have found a defect, open an issue. Do not deploy a proof against a live treasury.