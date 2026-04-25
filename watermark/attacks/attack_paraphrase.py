"""
attack_paraphrase.py
Attack 4 — Paraphrase (Offline Simulation)

A true paraphrase attack would call an LLM API, but for reproducible offline
experiments we simulate it via three compounding transformations:

  Step 1 — Sentence Shuffle:     Randomly reorder sentences (disrupts bigram HMACs)
  Step 2 — Synonym Substitution: Replace words at a moderate rate (changes surface form)
  Step 3 — Contraction Expansion / Reversal: Toggle contractions (changes token identity)

This approximates the effect of a paraphrase — the semantic content is largely
preserved but the exact token sequence is disrupted at multiple levels.

For the project demo, if an OpenAI/Anthropic API key is available, the
`attack_with_llm()` function can be used instead for a true paraphrase.
"""

import random
from typing import Optional
from ..core.tokenizer import tokenize_sentences, clean_text
from .attack_substitution import attack as synonym_attack

# ── Contraction map ──────────────────────────────────────────────────────────
EXPAND = {
    "can't":    "cannot",
    "won't":    "will not",
    "don't":    "do not",
    "doesn't":  "does not",
    "isn't":    "is not",
    "aren't":   "are not",
    "wasn't":   "was not",
    "weren't":  "were not",
    "it's":     "it is",
    "that's":   "that is",
    "they're":  "they are",
    "we're":    "we are",
    "you're":   "you are",
    "I'm":      "I am",
    "I've":     "I have",
    "I'll":     "I will",
    "we've":    "we have",
    "they've":  "they have",
}


def _toggle_contractions(text: str, rng: random.Random) -> str:
    """Randomly expand or collapse contractions."""
    for contraction, expansion in EXPAND.items():
        if contraction in text and rng.random() > 0.4:
            text = text.replace(contraction, expansion)
    return text


def attack(
    text: str,
    shuffle: bool = True,
    substitution_rate: float = 0.25,
    toggle_contractions: bool = True,
    seed: int = 42,
) -> str:
    """
    Offline paraphrase simulation combining sentence shuffle, synonym
    substitution, and contraction toggling.

    Args:
        text:                Input watermarked text.
        shuffle:             Whether to shuffle sentence order.
        substitution_rate:   Rate of synonym substitution applied.
        toggle_contractions: Whether to expand contractions.
        seed:                Reproducibility seed.

    Returns:
        Paraphrased text.
    """
    rng   = random.Random(seed)
    clean = clean_text(text)

    # Step 1 — sentence shuffle
    sentences = tokenize_sentences(clean)
    if shuffle and len(sentences) > 1:
        rng.shuffle(sentences)
    text_shuffled = ' '.join(sentences)

    # Step 2 — synonym substitution
    text_subst = synonym_attack(text_shuffled, substitution_rate=substitution_rate, seed=seed)

    # Step 3 — contraction toggling
    if toggle_contractions:
        text_final = _toggle_contractions(text_subst, rng)
    else:
        text_final = text_subst

    return text_final


# ── Optional: real LLM paraphrase ────────────────────────────────────────────

def attack_with_llm(text: str, api_key: str, model: str = "claude-sonnet-4-20250514") -> Optional[str]:
    """
    True paraphrase attack via Claude API.
    Requires anthropic package: pip install anthropic

    Only used if an API key is available.
    """
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=model,
            max_tokens=1024,
            messages=[{
                "role": "user",
                "content": (
                    "Please paraphrase the following text. "
                    "Preserve the meaning exactly but use different words and sentence structures. "
                    "Return only the paraphrased text, nothing else.\n\n" + text
                )
            }]
        )
        return msg.content[0].text
    except Exception as e:
        print(f"LLM paraphrase failed: {e}")
        return None


def attack_sweep(text: str, rates=None) -> dict:
    """Sweep substitution rates within the paraphrase attack."""
    if rates is None:
        rates = [0.1, 0.25, 0.4, 0.6]
    return {rate: attack(text, substitution_rate=rate) for rate in rates}
