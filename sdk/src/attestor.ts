import { Interface, Wallet, zeroPadValue } from "ethers";
import { attestationHash, type ActionLeaf, type AssetAmount, type Proposal } from "./encoding.js";
import { evaluate, type Policy } from "./policies.js";

export interface AttestationFields {
  proposalHash: string;
  policyHash: string;
  epoch: bigint;
  blockNumber: bigint;
  blockHash: string;
  attestor: string;
  scheme: string;
  verdict: number;
  expiresAt: bigint;
}

export interface TicketPreimage {
  proposalHash: string;
  mandateId: string;
  capId: string;
  capPathHash: string;
  agent: string;
  leafType: number;
  epoch: bigint;
  era: bigint;
  admitTime: bigint;
  windowLen: number;
  outageGrace: number;
  windowEnd: bigint;
  validUntil: bigint;
  pathMinExpiry: bigint;
  attestorsDigest: string;
  reserved: AssetAmount[];
  periodIdx: bigint[];
}

export function attestorId(address: string): string {
  return zeroPadValue(address, 32);
}

export function signAttestation(privateKey: string, chainId: bigint, gate: string, fields: AttestationFields): string {
  return new Wallet(privateKey).signingKey.sign(attestationHash(chainId, gate, fields)).serialized;
}

const withdrawIface = new Interface([
  "function withdrawAttestation((bytes32 proposalHash,bytes32 mandateId,bytes32 capId,bytes32 capPathHash,address agent,uint8 leafType,uint64 epoch,uint64 era,uint64 admitTime,uint32 windowLen,uint32 outageGrace,uint64 windowEnd,uint64 validUntil,uint64 pathMinExpiry,bytes32 attestorsDigest,(address asset,uint256 amount)[] reserved,uint64[] periodIdx) ticket, bytes32[] counted, uint256 idx)",
]);

function ticketTuple(t: TicketPreimage) {
  return [
    t.proposalHash,
    t.mandateId,
    t.capId,
    t.capPathHash,
    t.agent,
    t.leafType,
    t.epoch,
    t.era,
    t.admitTime,
    t.windowLen,
    t.outageGrace,
    t.windowEnd,
    t.validUntil,
    t.pathMinExpiry,
    t.attestorsDigest,
    t.reserved.map((x) => [x.asset, x.amount]),
    t.periodIdx,
  ];
}

export function withdrawCalldata(ticket: TicketPreimage, counted: string[], index: number): string {
  return withdrawIface.encodeFunctionData("withdrawAttestation", [ticketTuple(ticket), counted, index]);
}

export type ReviewResult =
  | { action: "keep"; reason: string }
  | { action: "withdrawAttestation"; reason: string; index: number; data: string };

/**
 * Reference attestor. A counted attestor withdraws if the revealed ticket no longer
 * matches the policy text. Withdrawal is a veto. This does not send a transaction.
 */
export function reviewInFlight(input: {
  policy: Policy;
  leaf: ActionLeaf;
  data: string;
  proposal: Proposal;
  ticket: TicketPreimage;
  countedAttestors: string[];
  attestor: string;
}): ReviewResult {
  const verdict = evaluate(input.policy, input.leaf, input.data, input.proposal);
  if (verdict.ok) return { action: "keep", reason: verdict.reason };
  const index = input.countedAttestors.findIndex((a) => a.toLowerCase() === input.attestor.toLowerCase());
  if (index < 0) return { action: "keep", reason: "policy fails, but this attestor was not counted" };
  return {
    action: "withdrawAttestation",
    reason: verdict.reason,
    index,
    data: withdrawCalldata(input.ticket, input.countedAttestors, index),
  };
}