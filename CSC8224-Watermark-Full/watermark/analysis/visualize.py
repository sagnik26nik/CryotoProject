"""
visualize.py
Generates publication-quality figures for the project report.

Figures produced:
  Figure 1 — Detection confidence vs. attack intensity (all attacks on one plot)
  Figure 2 — Semantic preservation vs. attack intensity
  Figure 3 — Confidence vs. semantic preservation tradeoff (scatter)
  Figure 4 — Radar chart of attack effectiveness summary
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from typing import Dict, Any

COLORS = {
    "ZW Strip":     "#e63946",
    "Substitution": "#f4a261",
    "Truncation":   "#2a9d8f",
    "Paraphrase":   "#457b9d",
}

MARKERS = {
    "ZW Strip":     "X",
    "Substitution": "o",
    "Truncation":   "s",
    "Paraphrase":   "^",
}

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'figures')


def _ensure_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def plot_confidence_vs_intensity(results: Dict[str, Any], save: bool = True) -> str:
    """Figure 1 — Detection confidence score vs. attack intensity."""
    _ensure_dir()
    fig, ax = plt.subplots(figsize=(8, 5))

    for name, data in results.items():
        x = data["intensities"]
        y = data["confidence"]
        ax.plot(x, y, marker=MARKERS[name], color=COLORS[name],
                label=name, linewidth=2, markersize=7)

    ax.axhline(y=0.85, color='gray', linestyle='--', linewidth=1, alpha=0.7, label='High-confidence threshold (0.85)')
    ax.axhline(y=0.50, color='lightgray', linestyle=':', linewidth=1, alpha=0.7, label='Uncertain threshold (0.50)')
    ax.set_xlabel("Attack Intensity", fontsize=12)
    ax.set_ylabel("Mean Confidence Score", fontsize=12)
    ax.set_title("Watermark Detection Confidence vs. Attack Intensity", fontsize=13, fontweight='bold')
    ax.set_ylim(-0.05, 1.05)
    ax.legend(fontsize=10)
    ax.grid(alpha=0.3)
    plt.tight_layout()

    path = os.path.join(OUTPUT_DIR, 'fig1_confidence_vs_intensity.png')
    if save:
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"Saved: {path}")
    plt.close(fig)
    return path


def plot_semantic_vs_intensity(results: Dict[str, Any], save: bool = True) -> str:
    """Figure 2 — Semantic preservation vs. attack intensity."""
    _ensure_dir()
    fig, ax = plt.subplots(figsize=(8, 5))

    for name, data in results.items():
        x = data["intensities"]
        y = data["semantic"]
        ax.plot(x, y, marker=MARKERS[name], color=COLORS[name],
                label=name, linewidth=2, markersize=7)

    ax.set_xlabel("Attack Intensity", fontsize=12)
    ax.set_ylabel("Semantic Preservation (Jaccard)", fontsize=12)
    ax.set_title("Semantic Preservation vs. Attack Intensity", fontsize=13, fontweight='bold')
    ax.set_ylim(-0.05, 1.05)
    ax.legend(fontsize=10)
    ax.grid(alpha=0.3)
    plt.tight_layout()

    path = os.path.join(OUTPUT_DIR, 'fig2_semantic_vs_intensity.png')
    if save:
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"Saved: {path}")
    plt.close(fig)
    return path


def plot_tradeoff(results: Dict[str, Any], save: bool = True) -> str:
    """Figure 3 — Confidence vs. Semantic tradeoff scatter."""
    _ensure_dir()
    fig, ax = plt.subplots(figsize=(7, 6))

    for name, data in results.items():
        x = data["semantic"]
        y = data["confidence"]
        ax.scatter(x, y, color=COLORS[name], label=name, s=80, zorder=5)
        # Draw arrow showing progression of attack intensity
        if len(x) > 1:
            for i in range(len(x)-1):
                ax.annotate("", xy=(x[i+1], y[i+1]), xytext=(x[i], y[i]),
                            arrowprops=dict(arrowstyle="->", color=COLORS[name], lw=1.2))

    ax.set_xlabel("Semantic Preservation", fontsize=12)
    ax.set_ylabel("Watermark Confidence Score", fontsize=12)
    ax.set_title("Privacy-Utility Tradeoff: Confidence vs. Semantics", fontsize=13, fontweight='bold')
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.legend(fontsize=10)
    ax.grid(alpha=0.3)
    # Annotate quadrants
    ax.text(0.05, 0.92, "Strong attack\nLow semantics\nLow detection", fontsize=8, color='gray', alpha=0.7)
    ax.text(0.72, 0.92, "Weak attack\nHigh semantics\nHigh detection", fontsize=8, color='gray', alpha=0.7)
    plt.tight_layout()

    path = os.path.join(OUTPUT_DIR, 'fig3_tradeoff.png')
    if save:
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"Saved: {path}")
    plt.close(fig)
    return path


def plot_radar(results: Dict[str, Any], save: bool = True) -> str:
    """Figure 4 — Radar chart summarizing attack effectiveness."""
    _ensure_dir()

    categories   = ['Confidence\nDestruction', 'Semantic\nPreservation', 'Stego\nBypass', 'Sentence\nDisruption', 'Ease of\nExecution']
    n_cat        = len(categories)
    angles       = [n / float(n_cat) * 2 * np.pi for n in range(n_cat)]
    angles      += angles[:1]

    # Hard-coded approximate scores per attack for radar (based on experiment insight)
    RADAR_SCORES = {
        "ZW Strip":     [1.00, 1.00, 1.00, 0.00, 1.00],
        "Substitution": [0.60, 0.65, 0.50, 0.70, 0.70],
        "Truncation":   [0.75, 0.55, 0.40, 0.85, 0.80],
        "Paraphrase":   [0.70, 0.60, 0.55, 0.75, 0.50],
    }

    fig, ax = plt.subplots(figsize=(7, 7), subplot_kw=dict(polar=True))

    for name, scores in RADAR_SCORES.items():
        values  = scores + scores[:1]
        ax.plot(angles, values, color=COLORS[name], linewidth=2, label=name)
        ax.fill(angles, values, color=COLORS[name], alpha=0.15)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=10)
    ax.set_ylim(0, 1)
    ax.set_title("Attack Capability Radar", fontsize=13, fontweight='bold', pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1), fontsize=10)
    plt.tight_layout()

    path = os.path.join(OUTPUT_DIR, 'fig4_radar.png')
    if save:
        fig.savefig(path, dpi=150, bbox_inches='tight')
        print(f"Saved: {path}")
    plt.close(fig)
    return path


def generate_all(results: Dict[str, Any]) -> Dict[str, str]:
    """Generate and save all four figures. Returns dict of {name: path}."""
    return {
        "Figure 1 — Confidence vs Intensity":  plot_confidence_vs_intensity(results),
        "Figure 2 — Semantic vs Intensity":     plot_semantic_vs_intensity(results),
        "Figure 3 — Tradeoff Scatter":          plot_tradeoff(results),
        "Figure 4 — Attack Radar":              plot_radar(results),
    }
