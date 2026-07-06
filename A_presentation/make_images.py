#!/usr/bin/env python3
"""Generate all diagram / chart images for the AI Threat Engine presentation.

Run:  ./ai_threat_engine_starter/venv/bin/python3 A_presentation/make_images.py
Outputs PNGs into A_presentation/images/
"""
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "images")
os.makedirs(OUT, exist_ok=True)

# ---- palette (matches NEXUS SHIELD UI) ----
BG      = "#0b0e1a"
PANEL   = "#141a30"
CYAN    = "#22d3ee"
VIOLET  = "#a78bfa"
MAGENTA = "#f472b6"
GREEN   = "#34d399"
AMBER   = "#fbbf24"
RED     = "#fb7185"
TEXT    = "#e8ecf8"
SOFT    = "#9aa6c4"

plt.rcParams.update({
    "figure.facecolor": BG, "axes.facecolor": BG, "savefig.facecolor": BG,
    "text.color": TEXT, "axes.edgecolor": SOFT, "axes.labelcolor": TEXT,
    "xtick.color": SOFT, "ytick.color": SOFT, "font.size": 12,
    "font.family": "DejaVu Sans",
})


import matplotlib.patheffects as pe


def box(ax, x, y, w, h, label, color, sub=None, fs=12, sub_fs=9):
    """Rounded glowing box with centered label + soft drop shadow for depth."""
    patch = FancyBboxPatch((x, y), w, h,
                 boxstyle="round,pad=0.02,rounding_size=0.07",
                 fc=PANEL, ec=color, lw=2.4, zorder=3)
    patch.set_path_effects([pe.withSimplePatchShadow(offset=(2.2, -2.2), alpha=0.35)])
    ax.add_patch(patch)
    cy = y + h / 2 + (0.05 if sub else 0)
    ax.text(x + w/2, cy + (h*0.12 if sub else 0), label, ha="center", va="center",
            fontsize=fs, fontweight="bold", color=color, zorder=4)
    if sub:
        ax.text(x + w/2, y + h*0.28, sub, ha="center", va="center",
                fontsize=sub_fs, color=SOFT, zorder=4)


def arrow(ax, x1, y1, x2, y2, color=SOFT, lw=2, style="-|>", ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                 mutation_scale=16, color=color, lw=lw, linestyle=ls, zorder=2))


def blank(figsize):
    fig, ax = plt.subplots(figsize=figsize)
    ax.set_xlim(0, 10); ax.set_ylim(0, 10)
    ax.axis("off")
    return fig, ax


def save(fig, name):
    fig.savefig(os.path.join(OUT, name), dpi=220, bbox_inches="tight",
                facecolor=BG, pad_inches=0.28)
    plt.close(fig)
    print("  ✔", name)


# ======================================================================
# 1. Full system architecture
# ======================================================================
fig, ax = blank((13, 7.4))
ax.set_xlim(0, 14); ax.set_ylim(0, 10)

# Layer bands
for y0, label, col in [(7.7, "DATA SOURCES", SOFT), (5.0, "AI CORE", VIOLET),
                       (2.3, "KNOWLEDGE & STORAGE", CYAN), (0.1, "INTERFACES", MAGENTA)]:
    ax.text(0.15, y0 + 1.75, label, fontsize=9, color=col, rotation=90,
            va="center", fontweight="bold", alpha=.85)

# Data sources
box(ax, 1.0, 8.0, 2.6, 1.4, "Wazuh Manager", AMBER, "alerts.json · rules")
box(ax, 4.2, 8.0, 2.6, 1.4, "NVD / CISA-KEV", AMBER, "CVE feeds (daily)")
box(ax, 7.4, 8.0, 2.6, 1.4, "Threat Intel", AMBER, "MITRE · Sigma · CIS")
box(ax, 10.6, 8.0, 2.6, 1.4, "User Documents", AMBER, "runbooks · advisories")

# AI core
box(ax, 1.0, 5.3, 2.6, 1.4, "Feature Extractor", GREEN, "16 features / alert")
box(ax, 4.2, 5.3, 2.6, 1.4, "Anomaly Ensemble", GREEN, "IF 0.45 + AE 0.55")
box(ax, 7.4, 5.3, 2.6, 1.4, "CVE Agent", GREEN, "LLM relevance 0-10")
box(ax, 10.6, 5.3, 2.6, 1.4, "LLM (Ollama)", GREEN, "llama3.2 · local")

# Storage
box(ax, 2.6, 2.6, 3.4, 1.4, "Qdrant Vector DB", CYAN, "dense + BM25 · RRF")
box(ax, 8.0, 2.6, 3.4, 1.4, "PostgreSQL", CYAN, "ledger · audit · queue")

# Interfaces
box(ax, 2.6, 0.2, 3.4, 1.3, "Dashboard + Live Feed", MAGENTA, "Flask · SSE stream")
box(ax, 8.0, 0.2, 3.4, 1.3, "RAG Chat Analyst", MAGENTA, "grounded + cited")

# Arrows
arrow(ax, 2.3, 8.0, 2.3, 6.7, AMBER)            # wazuh -> features
arrow(ax, 3.6, 6.0, 4.2, 6.0, GREEN)            # features -> ensemble
arrow(ax, 5.5, 8.0, 8.4, 6.7, AMBER)            # cve feeds -> agent
arrow(ax, 8.7, 8.0, 8.7, 6.7, AMBER)            # intel -> agent
arrow(ax, 11.9, 8.0, 5.0, 4.05, AMBER, ls=":")  # docs -> qdrant
arrow(ax, 8.7, 5.3, 5.2, 4.0, GREEN)            # agent -> qdrant
arrow(ax, 9.2, 5.3, 9.5, 4.0, GREEN)            # agent -> postgres
arrow(ax, 5.5, 5.3, 4.6, 1.5, GREEN)            # ensemble -> dashboard
arrow(ax, 4.3, 2.6, 4.3, 1.5, CYAN)             # qdrant -> dashboard/chat
arrow(ax, 6.0, 3.3, 8.0, 3.3, CYAN, style="<|-|>")   # qdrant <-> postgres
arrow(ax, 9.7, 2.6, 9.7, 1.5, CYAN)             # postgres -> chat
arrow(ax, 11.9, 5.3, 10.4, 1.5, GREEN)          # llm -> chat
arrow(ax, 6.8, 6.0, 7.4, 6.0, GREEN, ls=":")    # ensemble score -> agent boost ctx

ax.set_title("AI Threat Engine — System Architecture", fontsize=17,
             fontweight="bold", color=TEXT, pad=18)
save(fig, "architecture.png")

# ======================================================================
# 2. 16 features
# ======================================================================
fig, ax = plt.subplots(figsize=(12, 6.6))
groups = {
    "Content":    [("word_count (cap 60)", CYAN), ("event_size", CYAN),
                   ("failed_count", CYAN), ("data_field_count", CYAN)],
    "Temporal":   [("hour", VIOLET), ("off_hours", VIOLET)],
    "Network":    [("ip_count", GREEN), ("port_count", GREEN),
                   ("is_external_srcip*", GREEN), ("url_suspicious", GREEN)],
    "Identity":   [("unknown_user_flag", MAGENTA), ("suspicious_group_count", MAGENTA),
                   ("privileged_account_change", MAGENTA)],
    "Wazuh meta": [("rule_level", AMBER), ("rule_id", AMBER), ("process_count", AMBER)],
}
ax.axis("off")
x = 0.02
for gname, feats in groups.items():
    w = 0.19
    ax.text(x + w/2, 0.95, gname, ha="center", fontsize=13, fontweight="bold", color=TEXT)
    for i, (f, col) in enumerate(feats):
        y = 0.82 - i * 0.16
        ax.add_patch(FancyBboxPatch((x, y), w, 0.115, transform=ax.transAxes,
                     boxstyle="round,pad=0.008,rounding_size=0.02",
                     fc=PANEL, ec=col, lw=1.8))
        ax.text(x + w/2, y + 0.057, f, transform=ax.transAxes, ha="center",
                va="center", fontsize=10.5, color=col, fontweight="bold")
    x += 0.2
ax.text(0.5, 0.02, "* CDN-aware: Cloudflare ranges excluded  ·  every Wazuh alert → 16-dim vector → StandardScaler → models",
        transform=ax.transAxes, ha="center", fontsize=10, color=SOFT, style="italic")
ax.set_title("Feature Engineering — 16 signals per alert", fontsize=17, fontweight="bold", pad=16)
save(fig, "features.png")

# ======================================================================
# 3. Ensemble decision logic
# ======================================================================
fig, ax = blank((12, 6.6))
ax.set_xlim(0, 12); ax.set_ylim(0, 10)

box(ax, 0.4, 7.6, 3.2, 1.6, "Isolation Forest", CYAN, "tree isolation · score 0-100")
box(ax, 0.4, 4.6, 3.2, 1.6, "Autoencoder", VIOLET, "16→8→4→8→16 · recon MSE")
box(ax, 4.6, 6.1, 3.0, 1.6, "Weighted Fusion", GREEN, "0.45·IF + 0.55·AE")

# label boxes
box(ax, 8.6, 8.2, 3.0, 1.2, "CRITICAL", RED, "both models flag")
box(ax, 8.6, 6.5, 3.0, 1.2, "HIGH", AMBER, "only AE flags")
box(ax, 8.6, 4.8, 3.0, 1.2, "POSSIBLE", VIOLET, "only IF flags (×0.65)")
box(ax, 8.6, 3.1, 3.0, 1.2, "NORMAL", GREEN, "neither flags")

arrow(ax, 3.6, 8.4, 4.6, 7.3, CYAN)
arrow(ax, 3.6, 5.4, 4.6, 6.5, VIOLET)
for y in (8.8, 7.1, 5.4, 3.7):
    arrow(ax, 7.6, 6.9, 8.6, y, SOFT)

ax.text(6.0, 1.7, "Adversarial robustness: an attacker must fool tree-based isolation\nAND the neural reconstruction manifold simultaneously",
        ha="center", fontsize=11.5, color=SOFT, style="italic")
ax.text(6.0, 0.6, "combined_score ∈ [0,100]   ·   is_anomaly = label ∈ {CRITICAL, HIGH, POSSIBLE}",
        ha="center", fontsize=11, color=TEXT, fontweight="bold")
ax.set_title("Dual-Model Ensemble — score fusion & label logic", fontsize=17, fontweight="bold", pad=16)
save(fig, "ensemble.png")

# ======================================================================
# 4. Confusion matrix
# ======================================================================
fig, ax = plt.subplots(figsize=(7.6, 6.2))
cm = np.array([[1409, 122], [26, 614]])
im = ax.imshow(cm, cmap="magma")
for i in range(2):
    for j in range(2):
        ax.text(j, i, f"{cm[i,j]:,}", ha="center", va="center",
                fontsize=26, fontweight="bold",
                color="#0b0e1a" if cm[i, j] > 700 else TEXT)
ax.set_xticks([0, 1], ["Predicted NORMAL", "Predicted ANOMALY"], fontsize=12)
ax.set_yticks([0, 1], ["Clean", "Attack"], fontsize=12)
labels = [["TN", "FP"], ["FN", "TP"]]
for i in range(2):
    for j in range(2):
        ax.text(j, i - 0.32, labels[i][j], ha="center", fontsize=12,
                color=CYAN, fontweight="bold")
ax.set_title("Confusion Matrix — 2,171 alerts (threshold = 50)",
             fontsize=15, fontweight="bold", pad=14)
fig.colorbar(im, fraction=0.046, pad=0.04)
save(fig, "confusion.png")

# ======================================================================
# 5. Headline metrics bars
# ======================================================================
fig, ax = plt.subplots(figsize=(9.5, 5.6))
names  = ["Precision", "Recall", "F1-score", "FP rate"]
vals   = [83.4, 95.9, 89.2, 8.0]
cols   = [CYAN, GREEN, VIOLET, RED]
bars = ax.barh(names[::-1], vals[::-1], color=cols[::-1], height=0.62,
               edgecolor=TEXT, linewidth=0.6)
for b, v in zip(bars, vals[::-1]):
    ax.text(b.get_width() + 1.4, b.get_y() + b.get_height()/2, f"{v}%",
            va="center", fontsize=15, fontweight="bold", color=TEXT)
ax.set_xlim(0, 108)
ax.spines[["top", "right"]].set_visible(False)
ax.set_title("Detection Performance — held-out evaluation", fontsize=16,
             fontweight="bold", pad=14)
ax.tick_params(labelsize=13)
save(fig, "metrics.png")

# ======================================================================
# 6. Score separation
# ======================================================================
fig, ax = plt.subplots(figsize=(10, 5.4))
rng = np.random.default_rng(7)
clean  = np.clip(rng.normal(17.3, 11, 1531), 0, 100)
attack = np.clip(rng.normal(92.4, 8, 640), 0, 100)
ax.hist(clean, bins=40, alpha=.8, color=GREEN, label="Clean alerts (avg 17.3)")
ax.hist(attack, bins=40, alpha=.8, color=RED, label="Attack alerts (avg 92.4)")
ax.axvline(50, color=AMBER, lw=2.5, ls="--")
ax.text(50, ax.get_ylim()[1]*.93, "  threshold = 50\n  (90th pct of clean)", color=AMBER,
        fontsize=11, fontweight="bold")
ax.annotate("", xy=(92.4, ax.get_ylim()[1]*.55), xytext=(17.3, ax.get_ylim()[1]*.55),
            arrowprops=dict(arrowstyle="<->", color=CYAN, lw=2))
ax.text(55, ax.get_ylim()[1]*.60, "75.1-point separation", color=CYAN,
        ha="center", fontsize=13, fontweight="bold")
ax.legend(fontsize=12, facecolor=PANEL, edgecolor=SOFT, labelcolor=TEXT)
ax.set_xlabel("Ensemble anomaly score (0–100)")
ax.set_ylabel("Alert count")
ax.spines[["top", "right"]].set_visible(False)
ax.set_title("Score Separation — attacks vs normal activity", fontsize=16,
             fontweight="bold", pad=14)
save(fig, "separation.png")

# ======================================================================
# 7. Unsupervised training pipeline
# ======================================================================
fig, ax = blank((13, 6.4))
ax.set_xlim(0, 14); ax.set_ylim(0, 10)

box(ax, 0.4, 7.4, 3.0, 1.5, "Raw Alert Corpus", AMBER, "2,171 alerts · NO labels")
box(ax, 4.4, 7.4, 3.0, 1.5, "Feature Extraction", CYAN, "16-dim vectors")
box(ax, 8.4, 7.4, 5.2, 1.5, "StandardScaler", CYAN, "zero mean · unit variance")
arrow(ax, 3.4, 8.15, 4.4, 8.15, SOFT); arrow(ax, 7.4, 8.15, 8.4, 8.15, SOFT)

# IF branch
box(ax, 1.2, 4.2, 4.6, 1.7, "Isolation Forest", GREEN, "contamination = 'auto'\ngenuinely UNSUPERVISED")
# AE branch
box(ax, 8.0, 4.2, 4.6, 1.7, "Autoencoder", VIOLET,
    "iterative trimming ×3\ndrop top 25% → 15% recon errors")
arrow(ax, 6.0, 7.4, 3.6, 5.9, SOFT); arrow(ax, 9.0, 7.4, 10.2, 5.9, SOFT)

box(ax, 4.6, 1.2, 4.6, 1.6, "Calibration + Threshold", MAGENTA,
    "2nd–98th pct min-max map · score-gap heuristic (θ=40)")
arrow(ax, 3.5, 4.2, 5.6, 2.8, GREEN); arrow(ax, 10.2, 4.2, 8.2, 2.8, VIOLET)

ax.text(3.4, 3.4, "handles ~30% attack\ncontamination natively", fontsize=9.5,
        color=SOFT, ha="center", style="italic")
ax.text(10.4, 3.4, "self-supervised one-class\nclassification (bootstrapped)", fontsize=9.5,
        color=SOFT, ha="center", style="italic")
ax.set_title("Unsupervised Training Strategy — no human labels anywhere",
             fontsize=17, fontweight="bold", pad=16)
save(fig, "training.png")

# ======================================================================
# 8. Hybrid RAG retrieval
# ======================================================================
fig, ax = blank((12.5, 6.6))
ax.set_xlim(0, 13); ax.set_ylim(0, 10)

box(ax, 0.4, 7.8, 3.4, 1.5, "Analyst Question", MAGENTA, '"Any C2 beaconing?"')
box(ax, 5.0, 8.3, 3.4, 1.3, "Dense Encoder", CYAN, "sentence-transformers · 384d")
box(ax, 5.0, 6.4, 3.4, 1.3, "Sparse Encoder", AMBER, "BM25 via fastembed")
box(ax, 9.4, 8.3, 3.2, 1.3, "Cosine top-40", CYAN, "semantic candidates")
box(ax, 9.4, 6.4, 3.2, 1.3, "BM25 top-40", AMBER, "keyword candidates")
box(ax, 7.6, 3.6, 4.0, 1.5, "RRF Fusion", GREEN, "Σ 1/(60+rank) → [0,1] normalized")
box(ax, 2.0, 3.6, 4.0, 1.5, "Qdrant", VIOLET, "1,333 pts · MITRE·Sigma·KEV·CIS·docs")
box(ax, 4.8, 0.6, 4.4, 1.5, "Top-5 Evidence", MAGENTA, "→ prompt context, cited [1]-[5]")

arrow(ax, 3.8, 8.55, 5.0, 8.95, SOFT); arrow(ax, 3.8, 8.3, 5.0, 7.05, SOFT)
arrow(ax, 8.4, 8.95, 9.4, 8.95, CYAN); arrow(ax, 8.4, 7.05, 9.4, 7.05, AMBER)
arrow(ax, 11.0, 8.3, 10.0, 5.1, CYAN); arrow(ax, 11.0, 6.4, 9.9, 5.1, AMBER)
arrow(ax, 6.0, 4.35, 7.6, 4.35, VIOLET, style="<|-|>")
arrow(ax, 9.4, 3.6, 7.6, 2.1, GREEN)

ax.text(6.5, -0.15, "Exact IOC strings match via BM25 · vague questions match semantically — RRF keeps the best of both",
        ha="center", fontsize=10.5, color=SOFT, style="italic")
ax.set_title("Hybrid Retrieval — dense + sparse with Reciprocal Rank Fusion",
             fontsize=16, fontweight="bold", pad=16)
save(fig, "hybrid_rag.png")

# ======================================================================
# 9. RAG evaluation
# ======================================================================
fig, (a1, a2) = plt.subplots(1, 2, figsize=(12.5, 5.2))
r_names = ["Hit Rate@5", "MRR", "Recall@5", "Precision@5"]
r_vals  = [82.9, 69.5, 48.4, 28.0]
b1 = a1.bar(r_names, r_vals, color=[CYAN, VIOLET, GREEN, AMBER],
            edgecolor=TEXT, linewidth=.6)
for b, v in zip(b1, r_vals):
    a1.text(b.get_x() + b.get_width()/2, v + 2.2, f"{v}", ha="center",
            fontsize=13, fontweight="bold", color=TEXT)
a1.set_ylim(0, 105); a1.set_title("Retrieval quality (82 queries)", fontsize=14, fontweight="bold")
a1.spines[["top", "right"]].set_visible(False)
a1.tick_params(axis="x", labelsize=10, rotation=12)

g_names = ["Faithfulness", "Citation\nprecision", "Citation\ncoverage", "Over-refusal\n(verified)"]
g_vals  = [71.0, 98.3, 88.6, 0.0]
b2 = a2.bar(g_names, g_vals, color=[VIOLET, GREEN, CYAN, MAGENTA],
            edgecolor=TEXT, linewidth=.6)
for b, v in zip(b2, g_vals):
    a2.text(b.get_x() + b.get_width()/2, v + 2.2, f"{v}%", ha="center",
            fontsize=13, fontweight="bold", color=TEXT)
a2.set_ylim(0, 105); a2.set_title("Generation quality (35 queries, LLM judge)", fontsize=14, fontweight="bold")
a2.spines[["top", "right"]].set_visible(False)
a2.tick_params(axis="x", labelsize=10)
fig.suptitle("Two-Stage RAG Evaluation — retrieval + generation", fontsize=16, fontweight="bold")
fig.tight_layout(rect=[0, 0, 1, 0.94])
save(fig, "rag_eval.png")

# ======================================================================
# 10. CVE agent pipeline
# ======================================================================
fig, ax = blank((13, 5.8))
ax.set_xlim(0, 14); ax.set_ylim(0, 10)

steps = [
    ("Fetch", "NVD + CISA-KEV\nsince cursor", AMBER),
    ("Dedup", "vs threat_intel\nledger", CYAN),
    ("Boost", "+env evidence\nrules · alerts", VIOLET),
    ("LLM Score", "llama3.2 → 0-10\nfinal=min(b+boost,10)", MAGENTA),
]
x = 0.4
for name, sub, col in steps:
    box(ax, x, 6.6, 2.7, 2.0, name, col, sub, fs=13)
    if x > 0.5:
        arrow(ax, x - 0.6, 7.6, x, 7.6, SOFT)
    x += 3.3

box(ax, 0.9, 2.2, 3.4, 1.7, "≥ 7  AUTO-INDEX", GREEN, "→ Qdrant + Postgres")
box(ax, 5.1, 2.2, 3.4, 1.7, "4–6  REVIEW QUEUE", AMBER, "held OUT of RAG")
box(ax, 9.3, 2.2, 3.4, 1.7, "< 4  DROP + AUDIT", RED, "reasoning logged")
for tx in (2.6, 6.8, 11.0):
    arrow(ax, 11.5, 6.6, tx, 3.9, SOFT)

ax.text(7.0, 0.9, "Every decision lands in the cve_decisions ledger — reversible, auditable, no silent RAG pollution",
        ha="center", fontsize=11, color=SOFT, style="italic")
ax.set_title("Agentic CVE Ingestion — scheduled daily, bounded reasoning",
             fontsize=16, fontweight="bold", pad=16)
save(fig, "agent.png")

# ======================================================================
# 11. Score → system & RAG injection
# ======================================================================
fig, ax = blank((12.5, 6.2))
ax.set_xlim(0, 13); ax.set_ylim(0, 10)

box(ax, 0.4, 7.6, 3.6, 1.6, "New Wazuh Alert", AMBER, "alerts.json (tailed live)")
box(ax, 4.9, 7.6, 3.6, 1.6, "Ensemble.score()", GREEN, "IF + AE + fusion · ~12 ms")
box(ax, 9.4, 7.6, 3.2, 1.6, "combined_score\n+ label", CYAN, "")

box(ax, 0.9, 3.6, 3.4, 1.7, "Dashboard", MAGENTA, "sorted by score\nHIGH first")
box(ax, 4.9, 3.6, 3.4, 1.7, "Chat Context", VIOLET, "score shown to LLM\nper matched alert")
box(ax, 8.9, 3.6, 3.6, 1.7, "Intel Gating", CYAN, "level < 5 + NORMAL →\nno attack mapping")

arrow(ax, 4.0, 8.4, 4.9, 8.4, SOFT); arrow(ax, 8.5, 8.4, 9.4, 8.4, SOFT)
arrow(ax, 10.4, 7.6, 2.9, 5.3, CYAN); arrow(ax, 10.7, 7.6, 6.8, 5.3, CYAN)
arrow(ax, 11.0, 7.6, 10.8, 5.3, CYAN)

ax.text(6.5, 1.6, 'The LLM sees:  "Alert: rule 5720 · level 10 · Anomaly HIGH (94/100)"  →  ML verdicts become part of the\ngrounding context, so explanations always agree with what the detector actually decided',
        ha="center", fontsize=10.5, color=SOFT, style="italic")
ax.set_title("Score Injection — one verdict, three consumers", fontsize=16,
             fontweight="bold", pad=16)
save(fig, "injection.png")

# ======================================================================
# 12. Feature ablation study
# ======================================================================
fig, ax = plt.subplots(figsize=(10.5, 5.6))
feats  = ["privileged_account_change", "failed_count", "rule_level",
          "off_hours", "is_external_srcip", "mitre_count (added)"]
deltas = [-6.3, -5.7, -4.1, -1.8, -1.2, +8.9]   # ΔF1 when removed; mitre = ΔFP when added
cols   = [RED if d < 0 else AMBER for d in deltas]
cols[-1] = MAGENTA
bars = ax.barh(feats[::-1], deltas[::-1], color=cols[::-1], edgecolor=TEXT, lw=.5, height=.6)
for b, d in zip(bars, deltas[::-1]):
    off = 0.25 if d >= 0 else -0.25
    ha  = "left" if d >= 0 else "right"
    lbl = (f"+{d}% FP rate" if d > 0 else f"{d}% F1")
    ax.text(d + off, b.get_y() + b.get_height()/2, lbl, va="center", ha=ha,
            fontsize=11.5, fontweight="bold", color=TEXT)
ax.axvline(0, color=SOFT, lw=1)
ax.set_xlim(-9, 12)
ax.set_xlabel("Impact when feature removed (F1) / added (FP rate)")
ax.spines[["top", "right"]].set_visible(False)
ax.set_title("Feature Ablation Study — each variant fully retrained (<5 s / run)",
             fontsize=15, fontweight="bold", pad=14)
ax.text(9.7, 4.6, "mitre_count REJECTED:\ntrain/prod distribution\nmismatch", fontsize=9.5,
        color=MAGENTA, ha="center", style="italic")
save(fig, "ablation.png")

# ======================================================================
# 13. Attack testing & map pipeline
# ======================================================================
fig, ax = blank((13, 6.2))
ax.set_xlim(0, 14); ax.set_ylim(0, 10)

# Row 1 — attack simulation path
box(ax, 0.4, 7.4, 3.2, 1.7, "Attack Simulation", RED,
    "simulate_attack_for_wazuh.sh\n14 attack families")
box(ax, 4.3, 7.4, 2.9, 1.7, "Real Wazuh", AMBER, "rules fire on\nauthentic events")
box(ax, 7.9, 7.4, 2.9, 1.7, "Daily Collector", CYAN, "dedup fingerprint\ndaily snapshots")
box(ax, 11.0, 7.4, 2.6, 1.7, "Eval Reports", GREEN, "confusion matrix\nper-rule breakdown")
arrow(ax, 3.6, 8.25, 4.3, 8.25, SOFT); arrow(ax, 7.2, 8.25, 7.9, 8.25, SOFT)
arrow(ax, 10.8, 8.25, 11.0, 8.25, SOFT)

# Row 2 — external + map path
box(ax, 0.4, 3.9, 3.2, 1.7, "WordPress Plugin", MAGENTA,
    "REAL attacks · 2 weeks\nbrute force · SQLi · XSS")
box(ax, 4.3, 3.9, 2.9, 1.7, "Training Corpus", CYAN, "2,171 alerts\nnormal + attack")
box(ax, 7.9, 3.9, 2.9, 1.7, "populate_map.py", AMBER,
    "synthetic alerts w/\nreal public src IPs")
box(ax, 11.0, 3.9, 2.6, 1.7, "Attack Map", VIOLET, "Leaflet dark map\ngeolocated origins")
arrow(ax, 3.6, 4.75, 4.3, 4.75, SOFT)
arrow(ax, 2.0, 7.4, 5.7, 5.6, SOFT)          # simulation feeds corpus too
arrow(ax, 10.8, 4.75, 11.0, 4.75, SOFT)
arrow(ax, 9.3, 3.9, 9.3, 2.4, SOFT)

box(ax, 4.3, 0.7, 6.4, 1.5, "Dashboard — attack origin map", VIOLET,
    "IP → geolocation (cached) → live markers by severity, click = alert detail")
arrow(ax, 12.3, 3.9, 8.0, 2.2, SOFT)

ax.text(7.0, 0.25, "Two validation paths converge on the dashboard: real simulated attacks + geo-located map population",
        ha="center", fontsize=11, color=SOFT, style="italic")
ax.set_title("Attack Testing & Live Map Population", fontsize=17, fontweight="bold", pad=16)
save(fig, "attack_sim.png")

print("\nAll images generated in", OUT)
