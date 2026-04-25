"""
embedder.py
Hierarchical HMAC-SHA256 watermarking with steganographic zero-width character embedding.

Architecture:
  Layer 1 (Document)  — HMAC over full cleaned text          → 256-bit signature
  Layer 2 (Sentence)  — HMAC over each sentence              → per-sentence tag
  Layer 3 (Bigram)    — HMAC over sliding word bigrams        → fine-grained integrity

Embedding:
  Binary bits of the Layer-1 signature are encoded into inter-word positions
  using zero-width Unicode characters (invisible to readers):
    bit 0 → U+200B (Zero Width Space)
    bit 1 → U+200C (Zero Width Non-Joiner)
  A synchronization marker (U+2060 Word Joiner) is prepended so the verifier
  knows where the embedded payload begins.
"""

import hmac
import hashlib
import json
from typing import Dict, Any

from .tokenizer import tokenize_words, tokenize_sentences, ngrams, clean_text

# ── Zero-width character alphabet ────────────────────────────────────────────
ZW_0    = '\u200b'   # bit 0
ZW_1    = '\u200c'   # bit 1
ZW_SYNC = '\u2060'   # synchronization marker (payload start)
ZW_SEP  = '\u200d'   # sentence-boundary marker


def _hmac(key: str, message: str) -> str:
    """Compute HMAC-SHA256 and return as hex string."""
    return hmac.new(
        key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def _bits_from_hex(hex_str: str, n_bits: int) -> str:
    """Convert first n_bits of a hex digest to a binary string."""
    value = int(hex_str, 16)
    total_bits = len(hex_str) * 4
    binary = bin(value)[2:].zfill(total_bits)
    return binary[:n_bits]


def _encode_bits(bits: str) -> str:
    """Map a binary string to a zero-width character sequence."""
    return ''.join(ZW_1 if b == '1' else ZW_0 for b in bits)


def build_watermark(text: str, key: str, embed_bits: int = 64) -> Dict[str, Any]:
    """
    Compute the three-layer watermark metadata for a given text and secret key.

    Returns a dict with:
      - doc_hmac:      full 256-bit document-level HMAC
      - sentence_hmacs: list of per-sentence HMACs
      - bigram_hmacs:  list of bigram-window HMACs (first 20)
      - embed_payload: zero-width string to weave into the text
    """
    clean = clean_text(text)

    # Layer 1 — document
    doc_hmac = _hmac(key, clean)

    # Layer 2 — sentences
    sentences = tokenize_sentences(clean)
    sentence_hmacs = [_hmac(key, s) for s in sentences]

    # Layer 3 — bigrams (first 20 for feasibility)
    words = tokenize_words(clean)
    bigrams = ngrams(words, 2)
    bigram_hmacs = [_hmac(key, ' '.join(bg)) for bg in bigrams[:20]]

    # Payload: synchronization marker + encoded bits of doc HMAC
    bits = _bits_from_hex(doc_hmac, embed_bits)
    embed_payload = ZW_SYNC + _encode_bits(bits)

    return {
        'doc_hmac':       doc_hmac,
        'sentence_hmacs': sentence_hmacs,
        'bigram_hmacs':   bigram_hmacs,
        'embed_payload':  embed_payload,
        'embed_bits':     embed_bits,
    }


def embed(text: str, key: str, embed_bits: int = 64) -> str:
    """
    Embed the HMAC-derived zero-width payload into the text.

    Strategy: inject each zero-width bit character INSIDE the space between
    words (i.e., space + ZW_char + next_word). This guarantees that
    clean_text(embed(text)) == text exactly, since strip() removes only
    the invisible characters and leaves all spaces and words intact.
    """
    wm = build_watermark(text, key, embed_bits)
    payload = wm['embed_payload']
    words = text.split(' ')

    if len(words) < 2:
        return payload + text  # edge case: single word

    result = words[0]
    for i in range(1, len(words)):
        if i - 1 < len(payload):
            # Place ZW char BETWEEN the space and the next word
            result += ' ' + payload[i - 1] + words[i]
        else:
            result += ' ' + words[i]

    return result


def get_metadata(text: str, key: str, embed_bits: int = 64) -> str:
    """Return JSON-serialized watermark metadata (for report/demo purposes)."""
    wm = build_watermark(text, key, embed_bits)
    return json.dumps({
        'doc_hmac':        wm['doc_hmac'],
        'sentence_count':  len(wm['sentence_hmacs']),
        'bigram_count':    len(wm['bigram_hmacs']),
        'embed_bits':      wm['embed_bits'],
    }, indent=2)
