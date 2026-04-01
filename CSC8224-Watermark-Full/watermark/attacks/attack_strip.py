"""
attack_strip.py
Attack 1 — Zero-Width Character Stripping

The simplest and most complete attack: programmatically remove every zero-width
Unicode character from the text. This destroys the steganographic payload entirely
while leaving the visible content 100% intact.

This attack is trivially easy to implement but serves as an important baseline —
it shows that steganographic embedding alone is NOT a robust watermarking channel.
"""

from ..core.tokenizer import clean_text


def attack(text: str) -> str:
    """
    Strip all zero-width characters from text.
    Preserves all visible content exactly.
    """
    return clean_text(text)
