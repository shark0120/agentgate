> 已封存（2026-09-26）：F1 以帳戶模組取代託管模型，本目錄不參與編譯。第 12 條缺口在融合規格中的去向見 ../../SPEC.md §17.2。

# SMP S0 — Sealed Mandate Protocol 最小可驗證原語

規格 §15 S0 的實作：單一 L2、ERC-20 託管、P 為可公開驗證的受限謂詞。

```
forge test            # 38 個單元/模糊測試 + 4 條不變量（約 1 分鐘）
```

## 檔案

| 檔案 | 規格層 |
|---|---|
| `src/SealedMandateGate.sol` | L2 Registry + L3 Capability Graph + L7 Finality Gate，同一合約 |
| `src/verifiers/PublicPredicateVerifier.sol` | proofType 0：S0 公開謂詞 `P = {agent, perActCap, mayDelegate}` |
| `src/interfaces/IRefinementVerifier.sol` | S1 的 ZK / TEE / FHE verifier 接這個介面 |
| `test/SealedMandateGate.t.sol` | §16.4 V1–V8、§15 S0 里程碑、委派、出口、guardian |
| `test/invariant/GateInvariant.t.sol` | 守恆、託管 = Σ 開放根 remain、圖記帳、D 外位址永不收款 |

## 資產出口（完整清單）

1. `finalize` —— 授權仍存活、π 已驗證、預算已預留。
2. `reclaim` —— 根授權已撤銷或過期後，把未用託管退給 principal。整棵樹都死了才能呼叫，所以不會和閘門搶同一筆錢。

沒有 owner、沒有升級、沒有 verifier setter。guardian 只能單向停用某個 proofType，只會減少活性，不會多開出口。

## 規格缺口與本實作的處理

依嚴重度排序。前四項會影響 S1 的設計。

1. **π 只證「A ⊑ P」的話，知道 P 就等於有權限。** S0 的 P 是公開的，任何人都能對 D 裡任何位址造出合法精煉。S1 的 P 雖然密封，同樣的問題換了個形式：P 一外洩，所有人都成了授權執行者。這和規格自己的命題「計算 ≠ 權限」矛盾。
   → π 必須綁定一個承諾在 M 裡的評估者身分。S0 用 agent 簽 actDigest 當作 π 的必要合取項（不是充分條件）。S1 的 ZK 電路要把這把評估者公鑰當公開輸入。

2. **跨域（S2）說「世代與預算仍以源 Registry 為準」，又說「不引入新的信任根」，兩者矛盾。** 目標鏈的閘門要讀到源鏈的 epoch 和預算，只能靠橋、light client 或 storage proof，這些本身就是信任根。另一條路是事先把預算切塊鎖到目標域（本質上就是跨域委派），代價是撤銷要等訊息傳過去才生效。規格需要二選一，並寫明撤銷延遲的上限。

3. **§16.1 的 `delegate` 沒有證明參數。** P 是密封的，所以 Registry 沒辦法檢查 P′ ⇒ P、V′ 不弱於 V，也無法確認呼叫者「被 P 允許再委派」。
   → 加了 `proofType + delegationProof`，由 verifier 判斷。

4. **D′ ⊆ D 無法用 Merkle root 在委派當下檢查。**
   → 改成花費時檢查：路徑上每一層都要證明 dest ∈ D，有效集合就是各層 D 的交集，D′ ⊆ D 自動成立。代價是每筆 act 要附 O(depth) 個 Merkle proof，所以 `MAX_DEPTH = 4`。

5. **§16.2 的 actDigest 欄位不夠。**
   - 沒有 nonce：搭配「同一 digest 只收一次」，同一世代內兩筆一模一樣的合法付款永遠做不成。→ 加 `nonce`。
   - 沒有驗證合約位址：同一條鏈上部署兩個閘門就能互相重放（§13 的一次性鍵也漏了這項）。→ 加 `address(this)`。
   - 沒有綁 `vis_projection`：relayer 可以偷換給 solver 看的投影。→ 把 `keccak(visProjection)` 放進 digest。
   - 沒有報價時窗：pending 的候選會一直佔住預算直到授權過期。→ 加 `deadline`。

6. **撤銷和世代混在一起。** `revoke` 同時設 bit 又 epoch+1，如果撤銷是終局，epoch 就沒有多餘資訊。規格要決定是否另有非終局的 `rotate`（讓 pending 候選失效但授權繼續有效）。而子授權有自己的 epoch，「e′ ≥ e」就沒有意義。
   → 撤銷設為終局。子授權記錄委派當下父的 epoch（`parentEpoch`），父一前進，整棵子樹就失效。

7. **兩段式 submit/finalize 需要預留。** §5.1 只有委派用的 `budget_locked`，並行的候選會超額。§10 Atomicity 要求「驗證與外呼同一交易」，但兩段式的驗證發生在 submit。
   → 加 `reserved`。finalize 時重新檢查所有會變動的狀態（epoch、路徑存活、deadline、proofType 是否被停用）。verifier 和承諾都不可變，所以 π 的有效性在兩段之間不會改變。

8. **沒定義資產託管模型，也沒有退款出口。** 如果用 allowance 模式，閘門就不是唯一出口，預算也沒有實際資產擔保。如果用託管模式，撤銷或過期後的錢要有地方回去。
   → 採託管。`reclaim` 是第二個、範圍很窄的出口（見上）。規格應該把「唯一出口」改寫成「存活授權的唯一出口」。

9. **「停用證明類型」沒有說由誰執行。** 這其實是一個管理角色。
   → 設計成 guardian 只能單向停用。principal 的撤銷加退款完全不經過任何證明系統，所以 guardian 最多只能凍結活性。

10. **「V′ 不弱於 V」需要先定義 V 的偏序。** V 在鏈上只是 hash，只能比較是否相等。
    → S0 verifier 只接受 `V = PUBLIC`，避免 S0 的授權被誤認為密封的。

11. **§2.2 第 8 條（計算對 V 禁止的觀察者不可讀）不是鏈上可以檢查的性質。** 閘門只能相信 π 所宣稱的 vis_ok，實際保證來自證明系統本身（TEE 則來自 attestation）。規格應該把它標成「證明系統假設」，而不是閘門不變量。

12. **「撤銷代理人寫在 P 裡」需要證明才能驗證**（P 是密封的）。S0 沒有實作，撤銷權是路徑上任一層的 principal。

## 不在 S0 範圍

加密 P（S1）、DA 張貼（L1）、Vault 前態（L4）、Match Adapter（L6，S0 只把投影 emit 出去）、證明費用帳戶與操作者押金（§12）、跨域（S2）、rebasing 或 fee-on-transfer 代幣（issue 時用餘額差拒收 FoT）。
