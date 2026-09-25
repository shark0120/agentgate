# Side build for Safe bytecode

AgentGate's main Foundry profile uses `via_ir`. Safe v1.4.1 does not compile that way.
These projects compile the tagged Safe source with `via_ir` off and the same solc.

The clones are not in git. Before building:

```
git clone --branch v1.4.1 --depth 1 https://github.com/safe-global/safe-smart-account.git ../lib/safe-v1.4.1
git clone --branch v1.5.0 --depth 1 https://github.com/safe-global/safe-smart-account.git ../lib/safe-v1.5.0
```

The commits used for the committed bytecode are in `test/safe/bytecode/README.md`.
A shallow clone of the tag is enough to regenerate. Check `git rev-parse HEAD` against that file
if you need the same bytecode.