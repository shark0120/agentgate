import { Interface, keccak256, toUtf8Bytes, getAddress } from "ethers";
import type { ActionLeaf, AssetAmount, Proposal } from "./encoding.js";

export interface PolicyVerdict {
  ok: boolean;
  reason: string;
}

export interface VendorPaymentPolicy {
  kind: "vendor-payment";
  text: string;
  token: string;
  recipients: string[];
  maxAmount: bigint;
}

export interface DexRebalancePolicy {
  kind: "dex-rebalance";
  text: string;
  router: string;
  tokenIn: string;
  tokenOut: string;
  maxAmountIn: bigint;
  minOut: bigint;
}

export type Policy = VendorPaymentPolicy | DexRebalancePolicy;

const transfer = new Interface(["function transfer(address to, uint256 amount)"]);
const swap = new Interface([
  "function swap(address tokenIn, uint256 amountIn, address tokenOut, uint256 minOut, address to)",
]);

export function policyHash(text: string): string {
  return keccak256(toUtf8Bytes(text));
}

function same(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

function declared(xs: AssetAmount[], asset: string): bigint {
  const hit = xs.find((x) => same(x.asset, asset));
  return hit ? hit.amount : 0n;
}

export function evaluateVendor(policy: VendorPaymentPolicy, leaf: ActionLeaf, data: string, proposal: Proposal): PolicyVerdict {
  if (!same(leaf.target, policy.token)) return { ok: false, reason: "token is not the policy token" };
  if (leaf.selector !== transfer.getFunction("transfer").selector) return { ok: false, reason: "selector is not transfer" };
  let decoded: readonly [string, bigint];
  try {
    decoded = transfer.decodeFunctionData("transfer", data) as unknown as readonly [string, bigint];
  } catch {
    return { ok: false, reason: "calldata is not transfer(address,uint256)" };
  }
  const to = getAddress(decoded[0]);
  const amount = decoded[1];
  if (!policy.recipients.map(getAddress).includes(to)) return { ok: false, reason: "recipient is not a vendor" };
  if (amount > policy.maxAmount) return { ok: false, reason: "amount exceeds the vendor cap" };
  if (declared(proposal.declaredOut, policy.token) < amount) {
    return { ok: false, reason: "declared outflow is below the transfer amount" };
  }
  return { ok: true, reason: "vendor payment matches the policy text" };
}

export function evaluateDex(policy: DexRebalancePolicy, leaf: ActionLeaf, data: string, proposal: Proposal): PolicyVerdict {
  if (!same(leaf.target, policy.router)) return { ok: false, reason: "target is not the policy router" };
  if (leaf.selector !== swap.getFunction("swap").selector) return { ok: false, reason: "selector is not swap" };
  let decoded: { tokenIn: string; amountIn: bigint; tokenOut: string; minOut: bigint };
  try {
    const raw = swap.decodeFunctionData("swap", data);
    decoded = {
      tokenIn: raw.tokenIn as string,
      amountIn: raw.amountIn as bigint,
      tokenOut: raw.tokenOut as string,
      minOut: raw.minOut as bigint,
    };
  } catch {
    return { ok: false, reason: "calldata is not the reference swap" };
  }
  if (!same(decoded.tokenIn, policy.tokenIn) || !same(decoded.tokenOut, policy.tokenOut)) {
    return { ok: false, reason: "pair does not match the policy" };
  }
  if (decoded.amountIn > policy.maxAmountIn) return { ok: false, reason: "amount in exceeds the policy cap" };
  if (decoded.minOut < policy.minOut) return { ok: false, reason: "router minOut is below the policy floor" };
  if (declared(proposal.declaredMinIn, policy.tokenOut) < policy.minOut) {
    return { ok: false, reason: "declared minimum inflow is below the policy floor" };
  }
  return { ok: true, reason: "rebalance matches the policy text" };
}

export function evaluate(policy: Policy, leaf: ActionLeaf, data: string, proposal: Proposal): PolicyVerdict {
  return policy.kind === "vendor-payment"
    ? evaluateVendor(policy, leaf, data, proposal)
    : evaluateDex(policy, leaf, data, proposal);
}