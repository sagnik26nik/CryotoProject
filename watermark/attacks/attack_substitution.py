"""
attack_substitution.py
Attack 2 — Synonym Substitution

Replaces a controlled fraction of content words with synonyms drawn from a
hand-curated substitution dictionary (no external API needed — fully offline).

This attack targets both:
  - The steganographic payload (re-tokenization shifts bit positions)
  - The HMAC layer (any word change invalidates bigram HMACs)
  - The sentence-level HMAC (sentence changes once a word is replaced)

The substitution_rate parameter controls attack intensity (0.0–1.0).
"""

import random
from typing import List
from ..core.tokenizer import tokenize_words, clean_text

# ── Synonym dictionary (offline, no API) ────────────────────────────────────
SYNONYMS = {
    "important":    ["significant", "crucial", "vital", "essential"],
    "use":          ["utilize", "employ", "apply", "leverage"],
    "show":         ["demonstrate", "illustrate", "reveal", "indicate"],
    "large":        ["substantial", "considerable", "extensive", "vast"],
    "small":        ["minor", "limited", "minimal", "modest"],
    "fast":         ["rapid", "swift", "quick", "speedy"],
    "good":         ["effective", "beneficial", "favorable", "positive"],
    "bad":          ["poor", "adverse", "negative", "harmful"],
    "make":         ["create", "generate", "produce", "construct"],
    "get":          ["obtain", "acquire", "retrieve", "gain"],
    "find":         ["discover", "identify", "locate", "detect"],
    "need":         ["require", "demand", "necessitate"],
    "change":       ["modify", "alter", "transform", "adjust"],
    "new":          ["novel", "recent", "modern", "fresh"],
    "data":         ["information", "records", "content", "material"],
    "model":        ["system", "framework", "approach", "architecture"],
    "text":         ["content", "document", "passage", "material"],
    "method":       ["approach", "technique", "strategy", "procedure"],
    "result":       ["outcome", "finding", "output", "conclusion"],
    "study":        ["research", "investigation", "analysis", "examination"],
    "based":        ["grounded", "founded", "derived", "rooted"],
    "propose":      ["suggest", "introduce", "present", "offer"],
    "generate":     ["produce", "create", "output", "yield"],
    "detect":       ["identify", "recognize", "discover", "locate"],
    "embed":        ["encode", "insert", "incorporate", "integrate"],
    "secret":       ["private", "confidential", "hidden", "covert"],
    "key":          ["credential", "token", "signature", "identifier"],
    "verify":       ["confirm", "validate", "authenticate", "check"],
    "attack":       ["compromise", "breach", "undermine", "exploit"],
    "original":     ["authentic", "genuine", "source", "baseline"],
    "predict":      ["forecast", "estimate", "anticipate", "project"],
    "learn":        ["acquire", "absorb", "understand", "grasp"],
    "train":        ["optimize", "fit", "calibrate", "tune"],
    "network":      ["system", "architecture", "framework", "structure"],
    "language":     ["linguistic", "textual", "verbal", "discourse"],
    "human":        ["person", "individual", "user", "author"],
    "real":         ["actual", "genuine", "authentic", "true"],
    "simple":       ["straightforward", "basic", "elementary", "plain"],
    "complex":      ["intricate", "sophisticated", "elaborate", "advanced"],
}


def attack(text: str, substitution_rate: float = 0.3, seed: int = 42) -> str:
    """
    Replace `substitution_rate` fraction of substitutable words with synonyms.

    Args:
        text:               Input text (may contain zero-width chars).
        substitution_rate:  Fraction of eligible words to replace (0.0–1.0).
        seed:               Random seed for reproducibility.

    Returns:
        Modified text with synonyms substituted.
    """
    rng = random.Random(seed)
    clean = clean_text(text)
    words = clean.split(' ')
    result = []

    eligible_indices = [
        i for i, w in enumerate(words)
        if w.lower().rstrip('.,;:!?"\')') in SYNONYMS
    ]
    n_to_replace = max(1, int(len(eligible_indices) * substitution_rate))
    chosen = set(rng.sample(eligible_indices, min(n_to_replace, len(eligible_indices))))

    for i, word in enumerate(words):
        if i in chosen:
            stripped  = word.lower().rstrip('.,;:!?"\') ')
            suffix    = word[len(stripped.lstrip()):]         # preserve punctuation
            synonym   = rng.choice(SYNONYMS[stripped])
            # Preserve original capitalisation
            if word[0].isupper():
                synonym = synonym.capitalize()
            result.append(synonym + suffix)
        else:
            result.append(word)

    return ' '.join(result)


def attack_sweep(text: str, rates: List[float] = None) -> dict:
    """Run the attack across a range of substitution rates and return results dict."""
    if rates is None:
        rates = [0.1, 0.2, 0.3, 0.5, 0.7, 1.0]
    return {rate: attack(text, substitution_rate=rate) for rate in rates}
