"""Text scoring utilities for determining how 'English-like' a text is."""

import json
import os
from pathlib import Path

_DATA_DIR = Path(__file__).parent.parent / "data"

# Lazy-loaded caches
_english_freq = None
_english_words = None


def _load_english_freq() -> dict:
    """Load English letter frequencies from data file."""
    global _english_freq
    if _english_freq is None:
        with open(_DATA_DIR / "english_freq.json", "r") as f:
            _english_freq = json.load(f)
    return _english_freq


def _load_english_words() -> set:
    """Load English word list from data file."""
    global _english_words
    if _english_words is None:
        with open(_DATA_DIR / "english_words.txt", "r") as f:
            _english_words = set(
                word.strip().lower() for word in f if word.strip()
            )
    return _english_words


def english_score(text: str) -> float:
    """
    Score how 'English-like' a text is.

    Uses a combination of:
    - Letter frequency similarity (chi-squared test)
    - Common word matching

    Returns:
        A score where higher values indicate more English-like text.
        The score is normalized to roughly [0, 100].
    """
    if not text:
        return 0.0

    text_upper = text.upper()
    alpha_chars = [c for c in text_upper if c.isalpha()]

    if not alpha_chars:
        return 0.0

    # Letter frequency score (inverse chi-squared - lower chi-sq = higher score)
    freq = _load_english_freq()
    n = len(alpha_chars)
    counts = {}
    for c in alpha_chars:
        counts[c.lower()] = counts.get(c.lower(), 0) + 1

    chi_squared = 0.0
    for letter, expected_freq in freq.items():
        observed = counts.get(letter, 0)
        expected = expected_freq * n
        if expected > 0:
            chi_squared += ((observed - expected) ** 2) / expected

    # Normalize chi-squared: perfect English ~ 0-30, random ~ 200+
    freq_score = max(0, 100 - chi_squared)

    # Word matching score
    words = text_upper.split()
    english_words = _load_english_words()
    if words:
        word_matches = sum(
            1 for w in words
            if w.strip(".,!?;:'-\"()").lower() in english_words
        )
        word_score = (word_matches / len(words)) * 100
    else:
        word_score = 0

    # Combined score: weight frequency analysis more for short texts,
    # word matching more for longer texts
    if len(words) < 3:
        return freq_score
    else:
        return 0.4 * freq_score + 0.6 * word_score


def is_english(text: str, threshold: float = 40.0) -> bool:
    """
    Determine if text is likely English.

    Args:
        text: The text to check.
        threshold: Minimum score to consider as English (default: 40.0).

    Returns:
        True if the text scores above the threshold.
    """
    return english_score(text) >= threshold
