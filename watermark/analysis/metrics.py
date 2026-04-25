"""
metrics.py
Experimental analysis — runs all attacks at multiple intensities
and computes detection rate, confidence score, and semantic preservation.
"""

from typing import List, Dict, Any
from ..core.embedder import embed
from ..core.verifier  import verify
from ..core.tokenizer import clean_text
from .. import attacks


def semantic_preservation(original: str, attacked: str) -> float:
    """
    Simple token-overlap semantic preservation score (Jaccard).
    In the full report, this would be replaced with cosine similarity
    of sentence-transformer embeddings.
    """
    orig_tokens = set(clean_text(original).lower().split())
    atk_tokens  = set(clean_text(attacked).lower().split())
    if not orig_tokens:
        return 0.0
    return len(orig_tokens & atk_tokens) / len(orig_tokens | atk_tokens)


def run_experiment(
    texts: List[str],
    key: str = "secret-hmac-key-2026",
    embed_bits: int = 64,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Full experimental pipeline:
      1. Embed watermark into all texts.
      2. Apply each attack at multiple intensities.
      3. Verify and record confidence scores.
      4. Return structured results for plotting.

    Returns:
        results dict keyed by attack name, each containing:
          - intensities: list of attack parameter values
          - confidence:  mean confidence score across texts at each intensity
          - semantic:    mean semantic preservation at each intensity
    """
    results = {}

    # ── Pre-embed all texts ───────────────────────────────────────────────────
    watermarked = [embed(t, key, embed_bits) for t in texts]

    if verbose:
        print(f"Embedded watermarks into {len(texts)} text(s).\n")

    # ── Attack 1: Zero-width strip ────────────────────────────────────────────
    name = "ZW Strip"
    confs, sems = [], []
    for orig, wm in zip(texts, watermarked):
        attacked = attacks.strip(wm)
        vr = verify(attacked, orig, key, embed_bits)
        confs.append(vr.confidence_score)
        sems.append(semantic_preservation(orig, attacked))
    results[name] = {
        "intensities": [1.0],   # binary: either stripped or not
        "confidence":  [sum(confs)/len(confs)],
        "semantic":    [sum(sems)/len(sems)],
    }
    if verbose:
        print(f"[{name}] confidence={results[name]['confidence'][0]:.3f}  "
              f"semantic={results[name]['semantic'][0]:.3f}")

    # ── Attack 2: Synonym substitution sweep ─────────────────────────────────
    name  = "Substitution"
    rates = [0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 1.0]
    conf_by_rate, sem_by_rate = [], []
    for rate in rates:
        c_list, s_list = [], []
        for orig, wm in zip(texts, watermarked):
            attacked = attacks.substitute(wm, substitution_rate=rate)
            vr = verify(attacked, orig, key, embed_bits)
            c_list.append(vr.confidence_score)
            s_list.append(semantic_preservation(orig, attacked))
        conf_by_rate.append(sum(c_list)/len(c_list))
        sem_by_rate.append(sum(s_list)/len(s_list))
    results[name] = {"intensities": rates, "confidence": conf_by_rate, "semantic": sem_by_rate}
    if verbose:
        for r, c in zip(rates, conf_by_rate):
            print(f"[{name}] rate={r:.2f}  confidence={c:.3f}")

    # ── Attack 3: Truncation sweep ────────────────────────────────────────────
    name  = "Truncation"
    rates = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7]
    conf_by_rate, sem_by_rate = [], []
    for rate in rates:
        c_list, s_list = [], []
        for orig, wm in zip(texts, watermarked):
            attacked = attacks.truncate(wm, truncation_rate=rate)
            vr = verify(attacked, orig, key, embed_bits)
            c_list.append(vr.confidence_score)
            s_list.append(semantic_preservation(orig, attacked))
        conf_by_rate.append(sum(c_list)/len(c_list))
        sem_by_rate.append(sum(s_list)/len(s_list))
    results[name] = {"intensities": rates, "confidence": conf_by_rate, "semantic": sem_by_rate}
    if verbose:
        for r, c in zip(rates, conf_by_rate):
            print(f"[{name}] rate={r:.2f}  confidence={c:.3f}")

    # ── Attack 4: Paraphrase sweep ────────────────────────────────────────────
    name  = "Paraphrase"
    rates = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
    conf_by_rate, sem_by_rate = [], []
    for rate in rates:
        c_list, s_list = [], []
        for orig, wm in zip(texts, watermarked):
            attacked = attacks.paraphrase(wm, substitution_rate=rate)
            vr = verify(attacked, orig, key, embed_bits)
            c_list.append(vr.confidence_score)
            s_list.append(semantic_preservation(orig, attacked))
        conf_by_rate.append(sum(c_list)/len(c_list))
        sem_by_rate.append(sum(s_list)/len(s_list))
    results[name] = {"intensities": rates, "confidence": conf_by_rate, "semantic": sem_by_rate}
    if verbose:
        for r, c in zip(rates, conf_by_rate):
            print(f"[{name}] rate={r:.2f}  confidence={c:.3f}")

    return results
