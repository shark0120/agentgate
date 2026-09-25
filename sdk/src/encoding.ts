import { AbiCoder, concat, id, keccak256 } from "ethers";

export const coder = AbiCoder.defaultAbiCoder();

export const TAG = {
  proposal: id("SMP/F1/Proposal"),
  attestation: id("SMP/F1/Attestation"),
  ready: id("SMP/F1/Ready"),
  cosign: id("SMP/F1/CoSign"),
  root: id("SMP/F1/RootCap"),
  child: id("SMP/F1/ChildCap"),
  ecdsa: id("SMP/scheme/ecdsa"),
} as const;

const DOMAIN_TYPE = id(
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
);

export const commitType = [
  "bytes32",
  "address",
  "address",
  "bytes32",
  "bytes32",
  "bytes32",
  "bytes32",
  "bytes32",
  "bytes32",
  "bytes32",
  "uint64",
  "uint64",
  "address",
] as const;

export const leafType = [
  "uint8",
  "address",
  "bytes32",
  "address",
  "bytes4",
  "tuple(uint16,uint8,bytes32)[]",
  "address[]",
  "uint256[]",
  "address[]",
] as const;

export const proposalType = [
  "bytes32",
  "uint64",
  "bytes32[]",
  "bytes32",
  "bytes32",
  "uint256",
  "tuple(address,uint256)[]",
  "tuple(address,uint256)[]",
  "uint256",
  "uint64",
  "uint64",
  "tuple(uint64,bytes32)",
] as const;

export interface AssetAmount {
  asset: string;
  amount: bigint;
}

export interface ArgRule {
  offset: number;
  op: number;
  operand: string;
}

export interface ActionLeaf {
  leafType: number;
  target: string;
  codeHash: string;
  implementation: string;
  selector: string;
  argRules: ArgRule[];
  assets: string[];
  maxOutPerCall: bigint[];
  spenderAllowlist: string[];
}

export interface Proposal {
  mandateId: string;
  epoch: bigint;
  capPath: string[];
  leafHash: string;
  calldataHash: string;
  value: bigint;
  declaredOut: AssetAmount[];
  declaredMinIn: AssetAmount[];
  nonce: bigint;
  validAfter: bigint;
  validUntil: bigint;
  stateRef: { blockNumber: bigint; blockHash: string };
}

export interface MandateCommit {
  mandateId: string;
  principalAccount: string;
  rootDelegatee: string;
  scopeRoot: string;
  policyHash: string;
  attestorSetRoot: string;
  guardianSetRoot: string;
  paramsHash: string;
  budgetHash: string;
  accountConfigDigest: string;
  expiry: bigint;
  activateAfter: bigint;
  adapter: string;
}

export function amounts(xs: AssetAmount[]): [string, bigint][] {
  return xs.map((x) => [x.asset, x.amount]);
}

export function encodeLeaf(leaf: ActionLeaf): string {
  return coder.encode([`tuple(${leafType.join(",")})`], [[
    leaf.leafType,
    leaf.target,
    leaf.codeHash,
    leaf.implementation,
    leaf.selector,
    leaf.argRules.map((r) => [r.offset, r.op, r.operand]),
    leaf.assets,
    leaf.maxOutPerCall,
    leaf.spenderAllowlist,
  ]]);
}

export function encodeProposal(p: Proposal): string {
  return coder.encode([`tuple(${proposalType.join(",")})`], [[
    p.mandateId,
    p.epoch,
    p.capPath,
    p.leafHash,
    p.calldataHash,
    p.value,
    amounts(p.declaredOut),
    amounts(p.declaredMinIn),
    p.nonce,
    p.validAfter,
    p.validUntil,
    [p.stateRef.blockNumber, p.stateRef.blockHash],
  ]]);
}

export function encodeCommit(c: MandateCommit): string {
  return coder.encode([...commitType], [
    c.mandateId,
    c.principalAccount,
    c.rootDelegatee,
    c.scopeRoot,
    c.policyHash,
    c.attestorSetRoot,
    c.guardianSetRoot,
    c.paramsHash,
    c.budgetHash,
    c.accountConfigDigest,
    c.expiry,
    c.activateAfter,
    c.adapter,
  ]);
}

export function domainSeparator(chainId: bigint, verifyingContract: string): string {
  return keccak256(
    coder.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [DOMAIN_TYPE, id("SMP-AgentGate"), id("1"), chainId, verifyingContract],
    ),
  );
}

export function hashTyped(chainId: bigint, gate: string, structHash: string): string {
  return keccak256(concat(["0x1901", domainSeparator(chainId, gate), structHash]));
}

export function proposalHash(chainId: bigint, gate: string, p: Proposal): string {
  const inner = keccak256(coder.encode(["bytes32", "bytes32"], [TAG.proposal, keccak256(encodeProposal(p))]));
  return hashTyped(chainId, gate, inner);
}

export function attestationHash(
  chainId: bigint,
  gate: string,
  a: {
    proposalHash: string;
    policyHash: string;
    epoch: bigint;
    blockNumber: bigint;
    blockHash: string;
    attestor: string;
    scheme: string;
    verdict: number;
    expiresAt: bigint;
  },
): string {
  const inner = keccak256(
    coder.encode(
      ["bytes32", "bytes32", "bytes32", "uint64", "uint64", "bytes32", "bytes32", "bytes32", "uint8", "uint64"],
      [
        TAG.attestation,
        a.proposalHash,
        a.policyHash,
        a.epoch,
        a.blockNumber,
        a.blockHash,
        a.attestor,
        a.scheme,
        a.verdict,
        a.expiresAt,
      ],
    ),
  );
  return hashTyped(chainId, gate, inner);
}

export function readyHash(chainId: bigint, gate: string, commitHash: string): string {
  return hashTyped(chainId, gate, keccak256(coder.encode(["bytes32", "bytes32"], [TAG.ready, commitHash])));
}

export function coSignHash(chainId: bigint, gate: string, proposalHash_: string): string {
  return hashTyped(chainId, gate, keccak256(coder.encode(["bytes32", "bytes32"], [TAG.cosign, proposalHash_])));
}

export function rootCapId(mandateId: string, epoch: bigint): string {
  return keccak256(coder.encode(["bytes32", "bytes32", "uint64"], [TAG.root, mandateId, epoch]));
}

export function childCapId(mandateId: string, nonce: bigint): string {
  return keccak256(coder.encode(["bytes32", "bytes32", "uint256"], [TAG.child, mandateId, nonce]));
}

export function commitHash(c: MandateCommit): string {
  return keccak256(encodeCommit(c));
}

/** OpenZeppelin leaf: keccak256(bytes.concat(keccak256(preimage))). */
export function standardLeaf(preimage: string): string {
  return keccak256(concat([keccak256(preimage)]));
}

export function scopeLeaf(leaf: ActionLeaf): string {
  return standardLeaf(encodeLeaf(leaf));
}

export function attestorLeaf(attestor: string, scheme: string): string {
  return standardLeaf(coder.encode(["bytes32", "bytes32"], [attestor, scheme]));
}

export function guardianLeaf(who: string): string {
  return standardLeaf(coder.encode(["address"], [who]));
}

export function hashPair(a: string, b: string): string {
  const [x, y] = BigInt(a) < BigInt(b) ? [a, b] : [b, a];
  return keccak256(coder.encode(["bytes32", "bytes32"], [x, y]));
}

export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) throw new Error("empty merkle tree");
  let layer = leaves.slice();
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      next.push(i + 1 < layer.length ? hashPair(layer[i], layer[i + 1]) : layer[i]);
    }
    layer = next;
  }
  return layer[0];
}

export function merkleProof(leaves: string[], index: number): string[] {
  if (index < 0 || index >= leaves.length) throw new Error("leaf index out of range");
  const proof: string[] = [];
  let idx = index;
  let layer = leaves.slice();
  while (layer.length > 1) {
    const sib = idx ^ 1;
    if (sib < layer.length) proof.push(layer[sib]);
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      next.push(i + 1 < layer.length ? hashPair(layer[i], layer[i + 1]) : layer[i]);
    }
    layer = next;
    idx = Math.floor(idx / 2);
  }
  return proof;
}