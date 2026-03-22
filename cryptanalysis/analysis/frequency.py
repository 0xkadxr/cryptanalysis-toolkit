"""Frequency analysis tools for cryptanalysis."""

import json
from pathlib import Path
from collections import Counter

_DATA_DIR = Path(__file__).parent.parent / "data"

_english_freq_cache = None


def _load_english_freq() -> dict:
    """Load English letter frequencies."""
    global _english_freq_cache
    if _english_freq_cache is None:
        with open(_DATA_DIR / "english_freq.json", "r") as f:
            _english_freq_cache = json.load(f)
    return _english_freq_cache


def letter_frequency(text: str) -> dict:
    """
    Calculate the relative frequency of each letter in the text.

    Args:
        text: Input text (case insensitive).

    Returns:
        Dictionary mapping lowercase letters to their relative frequencies.
    """
    alpha_only = [c.lower() for c in text if c.isalpha()]
    total = len(alpha_only)
    if total == 0:
        return {}

    counts = Counter(alpha_only)
    return {letter: count / total for letter, count in counts.items()}


def bigram_frequency(text: str) -> dict:
    """
    Calculate the relative frequency of bigrams (letter pairs) in the text.

    Args:
        text: Input text (case insensitive).

    Returns:
        Dictionary mapping bigrams to their relative frequencies.
    """
    alpha_only = "".join(c.lower() for c in text if c.isalpha())
    total = len(alpha_only) - 1
    if total <= 0:
        return {}

    counts = Counter()
    for i in range(total):
        bigram = alpha_only[i : i + 2]
        counts[bigram] += 1

    return {bigram: count / total for bigram, count in counts.items()}


def compare_to_english(freq_dict: dict) -> float:
    """
    Compare a frequency distribution to standard English using chi-squared test.

    Args:
        freq_dict: Dictionary of letter frequencies (as returned by letter_frequency).

    Returns:
        Chi-squared statistic. Lower values indicate closer match to English.
    """
    english = _load_english_freq()
    chi_squared = 0.0

    for letter, expected in english.items():
        observed = freq_dict.get(letter, 0)
        if expected > 0:
            chi_squared += ((observed - expected) ** 2) / expected

    return chi_squared


def frequency_table(text: str) -> list:
    """
    Generate a sorted frequency table for display.

    Returns:
        List of (letter, count, frequency) tuples, sorted by frequency descending.
    """
    alpha_only = [c.lower() for c in text if c.isalpha()]
    total = len(alpha_only)
    if total == 0:
        return []

    counts = Counter(alpha_only)
    table = [
        (letter, count, count / total)
        for letter, count in counts.items()
    ]
    table.sort(key=lambda x: x[2], reverse=True)
    return table


def plot_frequency(freq_dict: dict, title: str = "Letter Frequency"):
    """
    Plot a bar chart of letter frequencies using matplotlib.

    Args:
        freq_dict: Dictionary of letter frequencies.
        title: Chart title.

    Returns:
        The matplotlib figure object.
    """
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        raise ImportError("matplotlib is required for plotting. Install with: pip install matplotlib")

    english = _load_english_freq()
    letters = sorted(english.keys())

    observed = [freq_dict.get(l, 0) for l in letters]
    expected = [english[l] for l in letters]

    fig, ax = plt.subplots(figsize=(12, 5))
    x = range(len(letters))
    width = 0.35

    ax.bar([i - width / 2 for i in x], observed, width, label="Observed", color="steelblue")
    ax.bar([i + width / 2 for i in x], expected, width, label="English", color="coral", alpha=0.7)

    ax.set_xlabel("Letter")
    ax.set_ylabel("Frequency")
    ax.set_title(title)
    ax.set_xticks(list(x))
    ax.set_xticklabels([l.upper() for l in letters])
    ax.legend()

    plt.tight_layout()
    return fig
