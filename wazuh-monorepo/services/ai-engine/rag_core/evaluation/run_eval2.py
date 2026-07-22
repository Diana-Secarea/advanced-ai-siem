import json, math, sys
sys.path.insert(0, "/home/sek/wazuh/wazuh-monorepo/services/ai-engine")
from rag_core.database.qdrant_store import QdrantStore
from rag_core.evaluation.retrieval_metrics import (
    hit_rate_at_k, reciprocal_rank, recall_at_k, precision_at_k)

def ndcg_at_k(retrieved, relevant, k=5):
    rel = set(relevant)
    dcg = sum((1.0/math.log2(i+2)) for i, r in enumerate(retrieved[:k]) if r in rel)
    ideal = sum((1.0/math.log2(i+2)) for i in range(min(len(rel), k)))
    return dcg/ideal if ideal else 0.0

K = 5
data = json.load(open("/home/sek/wazuh/wazuh-monorepo/services/ai-engine/rag_core/evaluation/eval_dataset_82.json"))
s = QdrantStore()

rows = []
for d in data:
    rids = [r["episode_id"] for r in s.search(query=d["query"], top_k=K)]
    rel = d["relevant"]
    rows.append({
        "cat": d["category"], "nrel": len(rel),
        "hr": hit_rate_at_k(rids, rel, K), "rr": reciprocal_rank(rids, rel),
        "rec": recall_at_k(rids, rel, K), "prec": precision_at_k(rids, rel, K),
        "ndcg": ndcg_at_k(rids, rel, K),
    })

def agg(rs):
    n = len(rs)
    return (sum(r["hr"] for r in rs)/n, sum(r["prec"] for r in rs)/n,
            sum(r["rec"] for r in rs)/n, sum(r["rr"] for r in rs)/n,
            sum(r["ndcg"] for r in rs)/n)

print("\n=== OVERALL (82 queries, hybrid dense+BM25 RRF, k=5) ===")
hr, pr, rc, mr, nd = agg(rows)
print(f"Hit Rate {hr:.1%} | Precision@5 {pr:.1%} | Recall@5 {rc:.1%} | MRR {mr:.3f} | nDCG@5 {nd:.3f}")

order = ["mitre-attack","cve-vulnerability","lateral-movement","c2-exfiltration","apt-group","wazuh-rules"]
label = {"mitre-attack":"MITRE ATT&CK techniques","cve-vulnerability":"CVE / vulnerability details",
         "lateral-movement":"Lateral movement TTPs","c2-exfiltration":"C2 / exfiltration patterns",
         "apt-group":"APT group profiles","wazuh-rules":"Wazuh rules and responses"}
print("\n=== PER-CATEGORY ===")
print(f"{'Category':<28}{'Q':>3}{'AvgRel':>8}{'HitRate':>9}{'Recall@5':>10}{'MRR':>8}{'nDCG@5':>9}")
for c in order:
    rs = [r for r in rows if r["cat"] == c]
    hr, pr, rc, mr, nd = agg(rs)
    avg = sum(r["nrel"] for r in rs)/len(rs)
    print(f"{label[c]:<28}{len(rs):>3}{avg:>8.1f}{hr:>8.1%}{rc:>9.1%}{mr:>8.3f}{nd:>9.3f}")
