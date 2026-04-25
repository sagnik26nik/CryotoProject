"""
main.py
────────────────────────────────────────────────────────────────────────────
Cryptographic Watermarking of AI-Generated Text
CSC 8224 — Cryptography | Georgia State University | Spring 2026
────────────────────────────────────────────────────────────────────────────

Usage:
  python main.py              # Run full demo + experiments + generate figures
  python main.py --demo-only  # Run interactive demo only (no figures)
  python main.py --figs-only  # Re-generate figures from saved results
"""

import sys
import json
import time
from watermark import embed, verify, build_watermark, get_metadata
from watermark import strip, substitute, truncate, paraphrase
from watermark.analysis.metrics   import run_experiment
from watermark.analysis.visualize import generate_all

# ── Sample AI-generated texts (used as test corpus) ──────────────────────────
SAMPLE_TEXTS = [
    (
        "Large language models have demonstrated remarkable capabilities in generating "
        "coherent and contextually relevant text across a wide range of domains. "
        "These systems are trained on vast corpora of human-written text, enabling them "
        "to produce outputs that are increasingly indistinguishable from human authorship. "
        "However, this capability raises serious concerns about academic integrity, "
        "misinformation, and the attribution of intellectual work. "
        "Detecting AI-generated content has therefore become a critical research challenge."
    ),
    (
        "Differential privacy provides a mathematical framework for bounding the "
        "information that any algorithm can leak about individual data points. "
        "When applied to machine learning, differential privacy mechanisms add "
        "carefully calibrated noise to model gradients during training, ensuring "
        "that the resulting model cannot be used to infer sensitive details about "
        "specific training examples. This approach has become foundational in "
        "privacy-preserving machine learning systems deployed at scale."
    ),
    (
        "Federated learning enables multiple parties to collaboratively train a "
        "shared machine learning model without exchanging raw data. "
        "Each participant computes local model updates on their private dataset "
        "and shares only these updates with a central aggregator. "
        "The aggregator combines the updates and distributes the improved model "
        "back to all participants. This architecture preserves data locality and "
        "reduces privacy risks associated with centralized data collection."
    ),
    (
        "The transformer architecture has fundamentally reshaped natural language processing. "
        "Its self-attention mechanism allows the model to weigh the relevance of "
        "every token against every other token in the input sequence, capturing "
        "long-range dependencies that recurrent networks struggle to model. "
        "Pre-training on large corpora followed by task-specific fine-tuning "
        "has proven to be a highly effective paradigm, yielding state-of-the-art "
        "performance across benchmarks in translation, summarization, and classification."
    ),
    (
        "Hash-based message authentication codes provide both data integrity and "
        "authentication guarantees. An HMAC is computed by applying a cryptographic "
        "hash function to the combination of a secret key and the message. "
        "Any modification to the message will produce a completely different HMAC value, "
        "making tampering immediately detectable to anyone who holds the secret key. "
        "HMAC-SHA256 is widely used in modern security protocols including TLS and JWT."
    ),
]

KEY    = "csc8224-watermark-key-nik-2026"
BITS   = 64
DIVIDER = "─" * 70


def print_header():
    print("\n" + "═" * 70)
    print("  CRYPTOGRAPHIC WATERMARKING OF AI-GENERATED TEXT")
    print("  HMAC-SHA256 + Steganographic Embedding + Multi-Layer Verification")
    print("  CSC 8224 Cryptography — Georgia State University — Spring 2026")
    print("═" * 70 + "\n")


def demo_single(text: str, key: str = KEY, bits: int = BITS):
    """Interactive demo on a single text showing embed → verify → attack pipeline."""
    print(DIVIDER)
    print("DEMO: Single Text Walkthrough")
    print(DIVIDER)

    # ── Embed ────────────────────────────────────────────────────────────────
    print("\n📄 ORIGINAL TEXT:")
    print(f"   {text[:120]}...")

    wm_text = embed(text, key, bits)
    meta    = json.loads(get_metadata(text, key, bits))

    print(f"\n🔏 WATERMARK METADATA:")
    print(f"   Document HMAC (SHA-256): {meta['doc_hmac'][:32]}...{meta['doc_hmac'][-8:]}")
    print(f"   Sentences signed:        {meta['sentence_count']}")
    print(f"   Bigrams signed:          {meta['bigram_count']}")
    print(f"   Embedded bits:           {meta['embed_bits']}")

    invisible_chars = sum(1 for c in wm_text if c in '\u200b\u200c\u200d\ufeff\u2060')
    print(f"   Invisible chars injected: {invisible_chars}")
    print(f"\n   (Watermarked text looks identical to human eye ✓)")

    # ── Verify clean ─────────────────────────────────────────────────────────
    print(f"\n{DIVIDER}")
    print("VERIFICATION — No Attack")
    print(DIVIDER)
    vr = verify(wm_text, text, key, bits)
    print(f"   Verdict:          {vr.verdict}")
    print(f"   Confidence Score: {vr.confidence_score:.4f}")
    for line in vr.detail:
        print(f"   {line}")

    # ── Run all 4 attacks and re-verify ──────────────────────────────────────
    attacks_to_run = [
        ("1. Zero-Width Strip",      strip(wm_text)),
        ("2. Synonym Substitution",  substitute(wm_text, substitution_rate=0.3)),
        ("3. Truncation (30%)",      truncate(wm_text, truncation_rate=0.3)),
        ("4. Paraphrase Simulation", paraphrase(wm_text, substitution_rate=0.3)),
    ]

    for attack_name, attacked_text in attacks_to_run:
        print(f"\n{DIVIDER}")
        print(f"ATTACK: {attack_name}")
        print(DIVIDER)
        vr = verify(attacked_text, text, key, bits)
        print(f"   Verdict:          {vr.verdict}")
        print(f"   Confidence Score: {vr.confidence_score:.4f}")
        print(f"   Bit Agreement:    {vr.bit_agreement*100:.1f}%")
        print(f"   Sentences Intact: {vr.sentences_intact}/{vr.sentences_total}")
        print(f"   Jaccard Sim:      {vr.jaccard_similarity*100:.1f}%")
        # Show first 100 chars of attacked text
        clean_preview = ''.join(c for c in attacked_text if c.isprintable())
        print(f"   Attacked text:    {clean_preview[:100]}...")


def run_full_experiment():
    """Run all attacks across all sample texts and generate figures."""
    print(f"\n{DIVIDER}")
    print("FULL EXPERIMENT — 5 texts × 4 attacks × multiple intensities")
    print(DIVIDER + "\n")

    t0 = time.time()
    results = run_experiment(
        texts    = SAMPLE_TEXTS,
        key      = KEY,
        embed_bits = BITS,
        verbose  = True,
    )
    elapsed = time.time() - t0
    print(f"\nExperiment completed in {elapsed:.2f}s")

    print(f"\n{DIVIDER}")
    print("GENERATING FIGURES...")
    print(DIVIDER)
    paths = generate_all(results)
    for name, path in paths.items():
        print(f"   {name}")
        print(f"   → {path}")

    return results


def main():
    demo_only = '--demo-only' in sys.argv
    figs_only = '--figs-only' in sys.argv

    print_header()

    if not figs_only:
        demo_single(SAMPLE_TEXTS[0])

    if not demo_only:
        run_full_experiment()

    print(f"\n{'═'*70}")
    print("  All done! Check /figures/ for publication-ready plots.")
    print("═" * 70 + "\n")


if __name__ == '__main__':
    main()
