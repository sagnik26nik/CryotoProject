"""
tokenizer.py
Lightweight tokenizer that splits text into words, sentences, and n-grams.
"""

import re
from typing import List, Tuple


def tokenize_words(text: str) -> List[str]:
    """Split text into word tokens, preserving punctuation as separate tokens."""
    return re.findall(r"\w+|[^\w\s]", text)


def tokenize_sentences(text: str) -> List[str]:
    """Split text into sentences using punctuation boundaries."""
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    return [s.strip() for s in sentences if s.strip()]


def ngrams(tokens: List[str], n: int) -> List[Tuple[str, ...]]:
    """Generate n-grams from a token list."""
    return [tuple(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]


def clean_text(text: str) -> str:
    """Strip all zero-width Unicode characters from text before processing."""
    ZW_CHARS = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u2060', '\u180e']
    for ch in ZW_CHARS:
        text = text.replace(ch, '')
    return text
