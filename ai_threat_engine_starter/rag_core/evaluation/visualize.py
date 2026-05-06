"""
RAG Retrieval Evaluation Visualizations

Generates charts from evaluation results:
1. Aggregate metrics bar chart
2. Per-category heatmap
3. Recall vs k line chart

Usage:
    cd /home/sek/wazuh/ai_threat_engine_starter
    ./venv/bin/python3 -m rag_core.evaluation.visualize
"""

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from rag_core.database.qdrant_store import QdrantStore
from rag_core.evaluation.retrieval_metrics import evaluate_retrieval

OUTPUT_DIR = PROJECT_ROOT / "data" / "eval_reports"
COLORS = {
    "green": "#22c55e",
    "red": "#ef4444",
    "blue": "#3b82f6",
    "orange": "#f59e0b",
    "purple": "#a855f7",
    "cyan": "#06b6d4",
    "gray": "#6b7280",
    "dark_bg": "#1a1a2e",
    "card_bg": "#16213e",
    "text": "#e2e8f0",
    "grid": "#334155",
}


def _style_ax(ax, title=""):
    ax.set_facecolor(COLORS["card_bg"])
    ax.set_title(title, color=COLORS["text"], fontsize=13, fontweight="bold", pad=12)
    ax.tick_params(colors=COLORS["text"], labelsize=9)
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])


def plot_aggregate(agg, output_path):
    """Bar chart of aggregate metrics."""
    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor(COLORS["dark_bg"])
    _style_ax(ax, f"Aggregate Retrieval Metrics (k={agg['k']})")

    metrics = ["hit_rate_at_k", "mrr", "recall_at_k", "precision_at_k"]
    labels = [f"Hit Rate@{agg['k']}", "MRR", f"Recall@{agg['k']}", f"Precision@{agg['k']}"]
    values = [agg[m] for m in metrics]
    colors = [COLORS["green"], COLORS["blue"], COLORS["orange"], COLORS["purple"]]

    bars = ax.bar(labels, values, color=colors, width=0.6, edgecolor="none")
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                f"{val:.1%}", ha="center", va="bottom", color=COLORS["text"],
                fontsize=12, fontweight="bold")

    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Score", color=COLORS["text"])
    ax.axhline(y=0.8, color=COLORS["gray"], linestyle="--", alpha=0.5, label="80% target")
    ax.legend(facecolor=COLORS["card_bg"], edgecolor=COLORS["grid"],
              labelcolor=COLORS["text"], fontsize=9)
    ax.grid(axis="y", color=COLORS["grid"], alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_path / "aggregate_metrics.png", dpi=150, facecolor=fig.get_facecolor())
    plt.close()
    print(f"  Saved aggregate_metrics.png")


def plot_category_heatmap(per_query, output_path):
    """Heatmap of metrics per category."""
    categories = {}
    for r in per_query:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"hit": [], "mrr": [], "recall": []}
        categories[cat]["hit"].append(r["hit_rate"])
        categories[cat]["mrr"].append(r["mrr"])
        categories[cat]["recall"].append(r["recall"])

    cat_names = sorted(categories.keys())
    metric_names = ["Hit Rate", "MRR", "Recall"]
    data = np.zeros((len(cat_names), 3))

    for i, cat in enumerate(cat_names):
        data[i, 0] = np.mean(categories[cat]["hit"])
        data[i, 1] = np.mean(categories[cat]["mrr"])
        data[i, 2] = np.mean(categories[cat]["recall"])

    fig, ax = plt.subplots(figsize=(7, max(6, len(cat_names) * 0.5)))
    fig.patch.set_facecolor(COLORS["dark_bg"])
    _style_ax(ax, "Per-Category Performance Heatmap")

    im = ax.imshow(data, cmap="RdYlGn", aspect="auto", vmin=0, vmax=1)

    ax.set_xticks(range(3))
    ax.set_xticklabels(metric_names, color=COLORS["text"])
    ax.set_yticks(range(len(cat_names)))
    ax.set_yticklabels(cat_names, color=COLORS["text"])

    for i in range(len(cat_names)):
        for j in range(3):
            val = data[i, j]
            text_color = "white" if val < 0.5 else "black"
            ax.text(j, i, f"{val:.0%}", ha="center", va="center",
                    color=text_color, fontsize=10, fontweight="bold")

    cbar = fig.colorbar(im, ax=ax, shrink=0.8)
    cbar.ax.tick_params(colors=COLORS["text"])

    plt.tight_layout()
    fig.savefig(output_path / "category_heatmap.png", dpi=150, facecolor=fig.get_facecolor())
    plt.close()
    print(f"  Saved category_heatmap.png")


def plot_recall_vs_k(retriever, eval_data, output_path):
    """Line chart of metrics at different k values."""
    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor(COLORS["dark_bg"])
    _style_ax(ax, "Metrics at Different k Values")

    k_values = [1, 3, 5, 10, 15, 20]
    hit_rates = []
    recalls = []
    mrrs = []

    for k in k_values:
        res = evaluate_retrieval(retriever, eval_data, k=k, verbose=False)
        a = res["aggregate"]
        hit_rates.append(a["hit_rate_at_k"])
        recalls.append(a["recall_at_k"])
        mrrs.append(a["mrr"])

    ax.plot(k_values, hit_rates, "o-", color=COLORS["green"], linewidth=2,
            markersize=8, label="Hit Rate@k")
    ax.plot(k_values, recalls, "s-", color=COLORS["orange"], linewidth=2,
            markersize=8, label="Recall@k")
    ax.plot(k_values, mrrs, "^-", color=COLORS["blue"], linewidth=2,
            markersize=8, label="MRR")

    for k_val, hr, rec, mrr in zip(k_values, hit_rates, recalls, mrrs):
        ax.annotate(f"{hr:.0%}", (k_val, hr), textcoords="offset points",
                    xytext=(0, 10), color=COLORS["green"], fontsize=8, ha="center")
        ax.annotate(f"{rec:.0%}", (k_val, rec), textcoords="offset points",
                    xytext=(0, -15), color=COLORS["orange"], fontsize=8, ha="center")

    ax.set_xlabel("k (top-k results)", color=COLORS["text"])
    ax.set_ylabel("Score", color=COLORS["text"])
    ax.set_ylim(0, 1.1)
    ax.set_xticks(k_values)
    ax.legend(facecolor=COLORS["card_bg"], edgecolor=COLORS["grid"],
              labelcolor=COLORS["text"])
    ax.grid(color=COLORS["grid"], alpha=0.3)

    plt.tight_layout()
    fig.savefig(output_path / "recall_vs_k.png", dpi=150, facecolor=fig.get_facecolor())
    plt.close()
    print(f"  Saved recall_vs_k.png")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Visualize RAG evaluation results")
    parser.add_argument("-k", type=int, default=5)
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    # Setup output
    output_path = Path(args.output) if args.output else OUTPUT_DIR
    output_path.mkdir(parents=True, exist_ok=True)

    # Load data
    dataset_path = Path(__file__).parent / "eval_dataset.json"
    with open(dataset_path) as f:
        eval_data = json.load(f)

    retriever = QdrantStore()

    # Run evaluation
    print(f"\nRunning evaluation (k={args.k})...")
    res = evaluate_retrieval(retriever, eval_data, k=args.k, verbose=False)

    # Generate all plots
    print(f"\nGenerating visualizations to {output_path}/")
    plot_aggregate(res["aggregate"], output_path)
    plot_category_heatmap(res["per_query"], output_path)
    plot_recall_vs_k(retriever, eval_data, output_path)

    print(f"\nAll charts saved to {output_path}/")
    print("Files:")
    for f in sorted(output_path.glob("*.png")):
        print(f"  {f.name}")


if __name__ == "__main__":
    main()
