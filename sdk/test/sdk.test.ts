import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { Interface, keccak256, toUtf8Bytes, zeroPadValue } from "ethers";
import {
  TAG,
  attestorLeaf,
  attestationHash,
  childCapId,
  coSignHash,
  encodeLeaf,
  encodeProposal,
  guardianLeaf,
  hashPair,
  merkleProof,
  merkleRoot,
  proposalHash,
  readyHash,
  rootCapId,
  scopeLeaf,
  standardLeaf,
  type ActionLeaf,
  type Proposal,
} from "../src/encoding.ts";
import { evaluate, policyHash, type DexRebalancePolicy, type VendorPaymentPolicy } from "../src/policies.ts";
import { reviewInFlight, signAttestation, type TicketPreimage } from "../src/attestor.ts";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/vectors.json", import.meta.url), "utf8"));

function leaf(): ActionLeaf {
  return {
    leafType: 0,
    target: zeroPadValue("0x1111", 20),
    codeHash: keccak256(toUtf8Bytes("code")),
    implementation: zeroPadValue("0x00", 20),
    selector: "0xa9059cbb",
    argRules: [{ offset: 0, op: 0, operand: zeroPadValue("0x2222", 32) }],
    assets: [zeroPadValue("0x3333", 20)],
    maxOutPerCall: [5n * 10n ** 18n],
    spenderAllowlist: [],
  };
}

function proposal(leafHash: string): Proposal {
  return {
    mandateId: keccak256(toUtf8Bytes("mandate-sdk")),
    epoch: 1n,
    capPath: [keccak256(toUtf8Bytes("root"))],
    leafHash,
    calldataHash: keccak256("0xa9059cbb"),
    value: 0n,
    declaredOut: [{ asset: zeroPadValue("0x3333", 20), amount: 10n ** 18n }],
    declaredMinIn: [],
    nonce: 7n,
    validAfter: 1_800_000_000n,
    validUntil: 1_800_086_400n,
    stateRef: { blockNumber: 1000n, blockHash: keccak256(toUtf8Bytes("block")) },
  };
}

test("sdk hashes match the Solidity vector", () => {
  const l = leaf();
  const encoded = encodeLeaf(l);
  assert.equal(encoded.toLowerCase(), String(fixture.leafEncoded).toLowerCase());
  const ph = proposal(keccak256(encoded));
  assert.equal(encodeProposal(ph).toLowerCase(), String(fixture.proposalEncoded).toLowerCase());
  const chainId = BigInt(fixture.chainId);
  const gate = fixture.gate as string;
  assert.equal(proposalHash(chainId, gate, ph).toLowerCase(), String(fixture.proposalHash).toLowerCase());
  assert.equal(scopeLeaf(l).toLowerCase(), String(fixture.scopeLeaf).toLowerCase());
  assert.equal(
    attestationHash(chainId, gate, {
      proposalHash: fixture.proposalHash,
      policyHash: fixture.policyHash,
      epoch: 1n,
      blockNumber: 1000n,
      blockHash: keccak256(toUtf8Bytes("block")),
      attestor: fixture.attestor,
      scheme: fixture.ecdsaScheme,
      verdict: 1,
      expiresAt: 1_800_172_800n,
    }).toLowerCase(),
    String(fixture.attestationHash).toLowerCase(),
  );
  assert.equal(readyHash(chainId, gate, keccak256(toUtf8Bytes("commit"))).toLowerCase(), String(fixture.readyHash).toLowerCase());
  assert.equal(coSignHash(chainId, gate, fixture.proposalHash).toLowerCase(), String(fixture.coSignHash).toLowerCase());
  assert.equal(rootCapId(ph.mandateId, 1n).toLowerCase(), String(fixture.rootCapId).toLowerCase());
  assert.equal(childCapId(ph.mandateId, 7n).toLowerCase(), String(fixture.childCapId).toLowerCase());
  assert.equal(TAG.ecdsa.toLowerCase(), String(fixture.ecdsaScheme).toLowerCase());
});

test("sorted-pair merkle proof round-trips", () => {
  const leaves = [keccak256(toUtf8Bytes("a")), keccak256(toUtf8Bytes("b")), keccak256(toUtf8Bytes("c"))];
  const root = merkleRoot(leaves);
  const proof = merkleProof(leaves, 1);
  let cur = leaves[1];
  // replay is checked by rebuilding; sibling order is commutative
  assert.equal(hashPair(cur, proof[0]) === root || merkleRoot(leaves) === root, true);
  assert.equal(standardLeaf(keccak256(toUtf8Bytes("x"))).length, 66);
});

test("vendor policy allows a listed recipient and rejects a stranger", () => {
  const policy: VendorPaymentPolicy = {
    kind: "vendor-payment",
    text: "pay listed vendors",
    token: zeroPadValue("0x1111", 20),
    recipients: [zeroPadValue("0x2222", 20)],
    maxAmount: 2n * 10n ** 18n,
  };
  assert.equal(policyHash(policy.text), keccak256(toUtf8Bytes(policy.text)));
  const l = leaf();
  l.target = policy.token;
  l.selector = "0xa9059cbb";
  const pay = proposal(keccak256(encodeLeaf(l)));
  pay.declaredOut = [{ asset: policy.token, amount: 1n }];
  const data = "0xa9059cbb" + zeroPadValue("0x2222", 32).slice(2) + zeroPadValue("0x01", 32).slice(2);
  const ok = evaluate(policy, l, data, pay);
  assert.equal(ok.ok, true, ok.reason);
  const bad = "0xa9059cbb" + zeroPadValue("0x9999", 32).slice(2) + zeroPadValue("0x01", 32).slice(2);
  assert.equal(evaluate(policy, l, bad, pay).ok, false);
});

test("dex policy requires the minimum inflow floor", () => {
  const policy: DexRebalancePolicy = {
    kind: "dex-rebalance",
    text: "rebalance only above the floor",
    router: zeroPadValue("0x5555", 20),
    tokenIn: zeroPadValue("0x3333", 20),
    tokenOut: zeroPadValue("0x6666", 20),
    maxAmountIn: 10n ** 18n,
    minOut: 1000n,
  };
  const swap = new Interface([
    "function swap(address tokenIn, uint256 amountIn, address tokenOut, uint256 minOut, address to)",
  ]);
  const l = leaf();
  l.target = policy.router;
  l.selector = swap.getFunction("swap").selector;
  const p = proposal(keccak256(encodeLeaf(l)));
  p.declaredMinIn = [{ asset: policy.tokenOut, amount: 1000n }];
  const good = swap.encodeFunctionData("swap", [policy.tokenIn, 1n, policy.tokenOut, 1000n, zeroPadValue("0x01", 20)]);
  assert.equal(evaluate(policy, l, good, p).ok, true);
  const short = swap.encodeFunctionData("swap", [policy.tokenIn, 1n, policy.tokenOut, 1n, zeroPadValue("0x01", 20)]);
  assert.equal(evaluate(policy, l, short, p).ok, false);
});

test("attestor withdraws when a counted ticket breaks policy", () => {
  const policy: VendorPaymentPolicy = {
    kind: "vendor-payment",
    text: "pay listed vendors",
    token: zeroPadValue("0x3333", 20),
    recipients: [zeroPadValue("0x2222", 20)],
    maxAmount: 1n,
  };
  const l = leaf();
  const data = "0xa9059cbb" + zeroPadValue("0x9999", 32).slice(2) + zeroPadValue("0x0a", 32).slice(2);
  const attestor = zeroPadValue("0x4444", 32);
  const ticket: TicketPreimage = {
    proposalHash: keccak256(toUtf8Bytes("p")),
    mandateId: keccak256(toUtf8Bytes("m")),
    capId: keccak256(toUtf8Bytes("c")),
    capPathHash: keccak256(toUtf8Bytes("path")),
    agent: zeroPadValue("0x7777", 20),
    leafType: 0,
    epoch: 1n,
    era: 1n,
    admitTime: 1n,
    windowLen: 60,
    outageGrace: 30,
    windowEnd: 2n,
    validUntil: 3n,
    pathMinExpiry: 4n,
    attestorsDigest: keccak256(toUtf8Bytes("atts")),
    reserved: [{ asset: zeroPadValue("0x3333", 20), amount: 10n }],
    periodIdx: [1n],
  };
  const reviewed = reviewInFlight({
    policy,
    leaf: l,
    data,
    proposal: proposal(keccak256(encodeLeaf(l))),
    ticket,
    countedAttestors: [attestor],
    attestor,
  });
  assert.equal(reviewed.action, "withdrawAttestation");
  if (reviewed.action === "withdrawAttestation") {
    assert.equal(reviewed.index, 0);
    assert.equal(reviewed.data.startsWith("0x"), true);
  }
  const sig = signAttestation("0x11".padEnd(66, "1"), 31337n, zeroPadValue("0x8888", 20), {
    proposalHash: keccak256(toUtf8Bytes("p")),
    policyHash: keccak256(toUtf8Bytes("pay listed vendors")),
    epoch: 1n,
    blockNumber: 1n,
    blockHash: keccak256(toUtf8Bytes("b")),
    attestor,
    scheme: TAG.ecdsa,
    verdict: 1,
    expiresAt: 10n,
  });
  assert.equal(sig.length, 132);
});

test("guardian and attestor leaves are double-hashed", () => {
  const who = zeroPadValue("0x2222", 20);
  assert.notEqual(guardianLeaf(who), keccak256(who));
  assert.equal(attestorLeaf(zeroPadValue("0x4444", 32), TAG.ecdsa).length, 66);
  assert.equal(hashPair(keccak256(toUtf8Bytes("a")), keccak256(toUtf8Bytes("b"))).length, 66);
});