"""
verifier.py
Multi-layer watermark verifier with fuzzy confidence scoring.

Verification Layers:
  1. Exact HMAC match         — did the document change at all?
  2. Steganographic recovery  — can we extract the embedded bits?
  3. Bit agreement score      — even if modified, how many bits survived?
  4. Sentence-level integrity — which sentences remain untouched?
  5. Fuzzy document match     — Jaccard similarity on token sets

Each layer contributes to a final confidence score in [0.0, 1.0].
"""

import hmac
import hashlib
import difflib
from dataclasses import dataclass, field
from typing import List, Optional

from .tokenizer import tokenize_words, tokenize_sentences, clean_text, ngrams
from .embedder import _hmac, _bits_from_hex, _encode_bits, ZW_0, ZW_1, ZW_SYNC


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    is_exact_match:         bool   = False
    stego_bits_recovered:   int    = 0
    stego_bits_expected:    int    = 0
    bit_agreement:          float  = 0.0   # fraction of bits that match
    sentences_intact:       int    = 0
    sentences_total:        int    = 0
    sentence_integrity:     float  = 0.0
    jaccard_similarity:     float  = 0.0
    confidence_score:       float  = 0.0   # weighted composite
    verdict:                str    = "NOT WATERMARKED"
    detail:                 List[str] = field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _jaccard(a: str, b: str) -> float:
    """Token-set Jaccard similarity between two strings."""
    sa = set(tokenize_words(a.lower()))
    sb = set(tokenize_words(b.lower()))
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)


def _extract_stego_bits(text: str) -> Optional[str]:
    """
    Scan the text for the sync marker and extract ALL subsequent ZW bit chars,
    skipping over regular (visible + space) characters between them.
    Bits are distributed one-per-word-gap so we must scan the full text.
    Returns None if no sync marker found.
    """
    if ZW_SYNC not in text:
        return None
    payload_start = text.index(ZW_SYNC) + 1
    bits = []
    for ch in text[payload_start:]:
        if ch == ZW_1:
            bits.append('1')
        elif ch == ZW_0:
            bits.append('0')
        # All other characters (visible text, spaces, other ZW) are skipped
    return ''.join(bits) if bits else None


# ── Main verify function ──────────────────────────────────────────────────────

def verify(
    received_text: str,
    original_text: str,
    key: str,
    embed_bits: int = 64,
) -> VerificationResult:
    """
    Verify whether received_text is a (possibly modified) watermarked version
    of original_text signed with key.
    """
    r = VerificationResult()
    r.stego_bits_expected = embed_bits

    clean_original = clean_text(original_text)
    clean_received  = clean_text(received_text)

    # ── Layer 1: Exact HMAC match ─────────────────────────────────────────────
    original_hmac = _hmac(key, clean_original)
    received_hmac = _hmac(key, clean_received)
    r.is_exact_match = hmac.compare_digest(original_hmac, received_hmac)
    if r.is_exact_match:
        r.detail.append("✅ Layer 1: Exact HMAC match — document unchanged.")
    else:
        r.detail.append("⚠️  Layer 1: HMAC mismatch — document was modified.")

    # ── Layer 2: Steganographic bit recovery ──────────────────────────────────
    extracted_bits = _extract_stego_bits(received_text)
    if extracted_bits:
        r.stego_bits_recovered = len(extracted_bits)
        expected_bits = _bits_from_hex(original_hmac, embed_bits)
        # Bit agreement over the recovered length
        compared = min(len(extracted_bits), len(expected_bits))
        matches = sum(a == b for a, b in zip(extracted_bits[:compared], expected_bits[:compared]))
        r.bit_agreement = matches / embed_bits  # penalise truncated recovery
        r.detail.append(
            f"🔍 Layer 2: Recovered {r.stego_bits_recovered}/{embed_bits} bits "
            f"({r.bit_agreement*100:.1f}% agreement)."
        )
    else:
        r.bit_agreement = 0.0
        r.detail.append("❌ Layer 2: No steganographic payload found — likely stripped.")

    # ── Layer 3: Sentence-level integrity ────────────────────────────────────
    orig_sentences = tokenize_sentences(clean_original)
    recv_sentences = tokenize_sentences(clean_received)
    r.sentences_total = len(orig_sentences)
    intact = 0
    for os in orig_sentences:
        orig_s_hmac = _hmac(key, os)
        for rs in recv_sentences:
            if hmac.compare_digest(orig_s_hmac, _hmac(key, rs)):
                intact += 1
                break
    r.sentences_intact   = intact
    r.sentence_integrity = intact / max(r.sentences_total, 1)
    r.detail.append(
        f"📝 Layer 3: {intact}/{r.sentences_total} sentences cryptographically intact "
        f"({r.sentence_integrity*100:.1f}%)."
    )

    # ── Layer 4: Fuzzy Jaccard similarity ────────────────────────────────────
    r.jaccard_similarity = _jaccard(clean_original, clean_received)
    r.detail.append(
        f"🔗 Layer 4: Jaccard token similarity = {r.jaccard_similarity*100:.1f}%."
    )

    # ── Composite confidence score ────────────────────────────────────────────
    # Weights: exact(0.35) + bit_agreement(0.30) + sentence_integrity(0.20) + jaccard(0.15)
    r.confidence_score = (
        0.35 * float(r.is_exact_match) +
        0.30 * r.bit_agreement         +
        0.20 * r.sentence_integrity    +
        0.15 * r.jaccard_similarity
    )

    # ── Verdict ───────────────────────────────────────────────────────────────
    if r.confidence_score >= 0.85:
        r.verdict = "✅ WATERMARKED (HIGH CONFIDENCE)"
    elif r.confidence_score >= 0.50:
        r.verdict = "⚠️  WATERMARKED (DEGRADED — ATTACKED)"
    elif r.confidence_score >= 0.20:
        r.verdict = "❓ UNCERTAIN — HEAVILY MODIFIED"
    else:
        r.verdict = "❌ NOT WATERMARKED"

    return r
