# Safe creation bytecode

These files are creation bytecode, not source. Tests deploy them with `create`.

Built from https://github.com/safe-global/safe-smart-account

| File | Tag | Commit |
| --- | --- | --- |
| safe-1.4.1.bin, factory-1.4.1.bin, handler-1.4.1.bin | v1.4.1 | bf943f80fec5ac647159d26161446ac5d716a294 |
| safe-1.5.0.bin, factory-1.5.0.bin, handler-1.5.0.bin | v1.5.0 | dc437e8fba8b4805d76bcbd1c668c9fd3d1e83be |

Compiler: solc 0.8.30, optimizer 200 runs, Cancun, `via_ir` off.

`via_ir` is off only for this side build. Safe v1.4.1 does not compile under the
project `via_ir` pipeline (stack too deep in unannotated assembly). AgentGate still
uses `via_ir`. This bytecode is the tagged source compiled here. It is not the
canonical mainnet singleton, which was compiled with solc 0.7.6.

To regenerate, clone the tag into `lib/safe-v1.4.1` or `lib/safe-v1.5.0` and run
`forge build --root safe-build/v141` or `safe-build/v150`. Those directories are
gitignored because the clones contain their own `.git`.