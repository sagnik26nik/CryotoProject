"""
attack_truncation.py
Attack 3 — Truncation

Removes a suffix fraction of the text. This attack:
  - Destroys document-level HMAC (different content = different hash)
  - Partially destroys stego payload if truncation hits the embedding zone
  - Destroys sentence-level HMACs for removed sentences
  - Tests whether partial texts can still be attributed to the watermarked source

Three truncation modes:
  'suffix'   — remove the last X% of the text (most common attack)
  'prefix'   — remove the first X% (destroys sync marker)
  'random'   — remove random sentences
"""

import random
from ..core.tokenizer import tokenize_sentences, clean_text


def attack(
    text: str,
    truncation_rate: float = 0.3,
    mode: str = 'suffix',
    seed: int = 42,
) -> str:
    """
    Truncate the text by removing a fraction of its content.

    Args:
        text:             Input text.
        truncation_rate:  Fraction of text to remove (0.0–1.0).
        mode:             'suffix' | 'prefix' | 'random'
        seed:             Random seed (used only for 'random' mode).

    Returns:
        Truncated text.
    """
    clean = clean_text(text)
    sentences = tokenize_sentences(clean)

    if not sentences:
        # Word-level fallback
        words = clean.split()
        keep = max(1, int(len(words) * (1 - truncation_rate)))
        if mode == 'prefix':
            return ' '.join(words[len(words) - keep:])
        return ' '.join(words[:keep])

    n_remove = max(1, int(len(sentences) * truncation_rate))
    n_keep   = max(1, len(sentences) - n_remove)

    if mode == 'suffix':
        kept = sentences[:n_keep]
    elif mode == 'prefix':
        kept = sentences[len(sentences) - n_keep:]
    elif mode == 'random':
        rng    = random.Random(seed)
        kept   = rng.sample(sentences, n_keep)
    else:
        raise ValueError(f"Unknown mode: {mode}. Use 'suffix', 'prefix', or 'random'.")

    return ' '.join(kept)


def attack_sweep(text: str, rates=None, mode: str = 'suffix') -> dict:
    """Run truncation attack across a range of rates."""
    if rates is None:
        rates = [0.1, 0.2, 0.3, 0.5, 0.7]
    return {rate: attack(text, truncation_rate=rate, mode=mode) for rate in rates}
