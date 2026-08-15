#!/usr/bin/env python3
# =============================================================================
# embed_semantic.py ── 第 3 層(任務1)：NLP 語意嵌入 + 未見模板偏離偵測
# =============================================================================
# 動機（補 DeepLog 的盲點）：
#   DeepLog 用整數 template_id，把模板當無意義符號 → 碰到「訓練沒見過的新模板」
#   只能一律當異常（FPR 高）。本層用 sentence-transformer 把模板的『文字語意』
#   轉成 384 維向量，讓「沒見過但語意相近」的模板能被理解，而非一律誤報。
#
# 兩個做法（都輸出）：
#   (A) 最近鄰語意距離：計算每個模板向量到「正常模板集合質心/最近鄰」的餘弦距離。
#       正常訓練集裡常見的模板距離小；語意上偏離的（如攻擊特有模板）距離大。
#   (B) Autoencoder 重建誤差：只用正常模板向量訓練一個 AE，重建誤差大 = 偏離正常。
#
# 未見模板泛化實驗：刻意「假裝沒看過」某個正常模板（leave-one-out），看語意距離
#   會不會把它誤判成異常 —— 對比「若用 template_id 硬比對，必然誤判」。
#
# 執行： ml/venv/bin/python ml/embed_semantic.py
# 輸出： ml/out/semantic_results.txt, ml/out/template_embeddings.npy
# =============================================================================
import os
import numpy as np
import pandas as pd
from numpy.linalg import norm

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "out")
np.random.seed(42)

def cos_sim(a, b):
    return (a @ b) / (norm(a) * norm(b) + 1e-9)

def main():
    df = pd.read_csv(os.path.join(OUT, "parsed_all.csv"))
    log = []
    def out(s=""):
        print(s); log.append(str(s))

    # ---- 模板字典 + 標記每個模板是否「只在攻擊中出現」（供分析）----
    tmpl = df.groupby("template_id").agg(
        template=("template", "first"),
        count=("template_id", "size"),
        n_attack=("label", "sum"),
        in_baseline=("scenario", lambda s: any(x.startswith("baseline") for x in s)),
    ).reset_index()
    tmpl["attack_only"] = (tmpl["n_attack"] > 0) & (~tmpl["in_baseline"])

    out("="*68)
    out("第3層 語意嵌入 (sentence-transformer all-MiniLM-L6-v2, 384維)")
    out("="*68)
    out(f"模板數: {len(tmpl)}")

    # ---- 嵌入所有模板 ----
    from sentence_transformers import SentenceTransformer
    model = SentenceTransformer("all-MiniLM-L6-v2")
    emb = model.encode(tmpl["template"].tolist(), show_progress_bar=False,
                       normalize_embeddings=True)
    np.save(os.path.join(OUT, "template_embeddings.npy"), emb)
    tmpl_emb = {tid: emb[i] for i, tid in enumerate(tmpl["template_id"])}

    # ---- 定義「正常模板集合」= 出現在 baseline 的模板 ----
    normal_idx = tmpl.index[tmpl["in_baseline"]].tolist()
    normal_emb = emb[normal_idx]
    normal_centroid = normal_emb.mean(axis=0)

    # =========================================================================
    # (A) 最近鄰語意距離：每個模板到「正常模板集合」的最小餘弦距離
    # =========================================================================
    out("\n" + "-"*68)
    out("(A) 語意距離：每個模板到最近的『正常模板』的餘弦距離 (0=完全相同)")
    out("-"*68)
    rows = []
    for i, tid in enumerate(tmpl["template_id"]):
        # 到所有正常模板的最大相似度 → 距離 = 1 - max_sim（排除自己）
        sims = [cos_sim(emb[i], normal_emb[j]) for j in range(len(normal_emb))
                if not (tmpl.iloc[normal_idx[j]]["template_id"] == tid)]
        nn_dist = 1 - max(sims) if sims else 0.0
        rows.append((tid, tmpl.iloc[i]["attack_only"], nn_dist,
                     tmpl.iloc[i]["template"][:60]))
    rr = pd.DataFrame(rows, columns=["tid", "attack_only", "nn_dist", "tmpl"])
    rr = rr.sort_values("nn_dist", ascending=False)
    out("語意距離最大的 8 個模板（最『不像正常』的）:")
    for _, r in rr.head(8).iterrows():
        flag = "ATTACK-ONLY" if r["attack_only"] else "normal     "
        out(f"  dist={r['nn_dist']:.3f}  [{flag}]  {r['tmpl']}")
    # 攻擊專屬模板 vs 正常模板 的語意距離分布
    ao = rr[rr.attack_only]["nn_dist"]
    nm = rr[~rr.attack_only]["nn_dist"]
    out(f"\n攻擊專屬模板 語意距離: mean={ao.mean():.3f} (n={len(ao)})")
    out(f"正常模板     語意距離: mean={nm.mean():.3f} (n={len(nm)})")
    out("→ 若攻擊專屬模板的語意距離明顯較大，代表語意嵌入能靠『語意偏離』分辨，")
    out("  不需要死記 template_id（這就是對『未見模板』的泛化來源）。")

    # =========================================================================
    # (B) Autoencoder 重建誤差（只用正常模板向量訓練）
    # =========================================================================
    out("\n" + "-"*68)
    out("(B) Autoencoder 重建誤差（只用正常模板向量訓練，誤差大=偏離正常）")
    out("-"*68)
    import torch, torch.nn as nn
    torch.manual_seed(42)
    Xn = torch.tensor(normal_emb, dtype=torch.float32)
    ae = nn.Sequential(nn.Linear(384, 64), nn.ReLU(), nn.Linear(64, 16), nn.ReLU(),
                       nn.Linear(16, 64), nn.ReLU(), nn.Linear(64, 384))
    opt = torch.optim.Adam(ae.parameters(), lr=1e-3)
    lossf = nn.MSELoss()
    for ep in range(300):
        opt.zero_grad(); rec = ae(Xn); loss = lossf(rec, Xn); loss.backward(); opt.step()
    ae.eval()
    with torch.no_grad():
        allX = torch.tensor(emb, dtype=torch.float32)
        rec_err = ((ae(allX) - allX)**2).mean(dim=1).numpy()
    rr2 = pd.DataFrame({"tid": tmpl["template_id"], "attack_only": tmpl["attack_only"],
                        "rec_err": rec_err, "tmpl": tmpl["template"].str.slice(0,60)})
    rr2 = rr2.sort_values("rec_err", ascending=False)
    out("重建誤差最大的 8 個模板:")
    for _, r in rr2.head(8).iterrows():
        flag = "ATTACK-ONLY" if r["attack_only"] else "normal     "
        out(f"  err={r['rec_err']:.4f}  [{flag}]  {r['tmpl']}")
    ao2 = rr2[rr2.attack_only]["rec_err"]; nm2 = rr2[~rr2.attack_only]["rec_err"]
    out(f"\n攻擊專屬模板 重建誤差: mean={ao2.mean():.4f}")
    out(f"正常模板     重建誤差: mean={nm2.mean():.4f}")

    # =========================================================================
    # (C) 未見模板泛化實驗（leave-one-out）
    # =========================================================================
    out("\n" + "-"*68)
    out("(C) 未見模板泛化：假裝沒看過某個『正常』模板，語意法會不會誤判它為異常")
    out("-"*68)
    # 挑一個常見正常模板（如 Motor Received distance），把它從正常集拿掉，
    # 看它到剩餘正常模板的語意距離是否仍小（=不會被誤判）。
    target = tmpl[tmpl["template"].str.contains("Received distance", na=False)]
    if len(target):
        ti = target.index[0]
        rest = [j for j in normal_idx if j != ti]
        sims = [cos_sim(emb[ti], emb[j]) for j in rest]
        d = 1 - max(sims)
        nn_j = rest[int(np.argmax(sims))]
        out(f"目標(假裝未見): {tmpl.iloc[ti]['template'][:55]}")
        out(f"  到最近正常模板的語意距離 = {d:.3f}")
        out(f"  最近鄰是: {tmpl.iloc[nn_j]['template'][:55]}")
        out(f"→ 距離小 = 語意法把這個『未見但正常』的模板正確視為正常（不誤報）。")
        out(f"  對比：若用 template_id 硬比對，未見 ID 必被當異常 → 語意法的泛化優勢。")

    out("\n" + "="*68)
    out("小結")
    out("="*68)
    out("- 語意嵌入讓『模板文字』有意義：攻擊專屬模板因語意偏離而距離/誤差較大，")
    out("  可在『不死記 template_id』下被標記，並對『未見但語意正常』的模板不誤報。")
    out("- 侷限：R 偽造模板的語意（Motor 動作）與正常 motor 訊息相近，語意法對 R 幫助")
    out("  有限 → 再次印證 R 需靠 log 端簽章，非內容/語意可解。")

    open(os.path.join(OUT, "semantic_results.txt"), "w", encoding="utf-8").write(
        "\n".join(str(x) for x in log) + "\n")
    print(f"\n報告已存: {OUT}/semantic_results.txt")

if __name__ == "__main__":
    main()
