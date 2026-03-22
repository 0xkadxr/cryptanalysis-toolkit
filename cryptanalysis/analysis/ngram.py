"""N-gram analysis tools for cryptanalysis."""

from collections import Counter
from ..utils.alphabet import clean_text


def ngram_frequency(text: str, n: int = 2) -> dict:
    """
    Calculate the frequency of n-grams in the text.

    Args:
        text: Input text.
        n: Length of the n-gram (default: 2 for bigrams).

    Returns:
        Dictionary mapping n-grams to their relative frequencies.
    """
    cleaned = clean_text(text).lower()
    total = len(cleaned) - n + 1
    if total <= 0:
        return {}

    counts = Counter()
    for i in range(total):
        ngram = cleaned[i : i + n]
        counts[ngram] += 1

    return {ngram: count / total for ngram, count in counts.items()}


def top_ngrams(text: str, n: int = 2, top_k: int = 20) -> list:
    """
    Get the top-k most frequent n-grams in the text.

    Args:
        text: Input text.
        n: Length of the n-gram.
        top_k: Number of top n-grams to return.

    Returns:
        List of (ngram, frequency) tuples, sorted by frequency descending.
    """
    freqs = ngram_frequency(text, n)
    sorted_ngrams = sorted(freqs.items(), key=lambda x: x[1], reverse=True)
    return sorted_ngrams[:top_k]


def ngram_count(text: str, n: int = 2) -> dict:
    """
    Count occurrences of n-grams (raw counts, not frequencies).

    Args:
        text: Input text.
        n: Length of the n-gram.

    Returns:
        Dictionary mapping n-grams to their counts.
    """
    cleaned = clean_text(text).lower()
    counts = Counter()
    for i in range(len(cleaned) - n + 1):
        ngram = cleaned[i : i + n]
        counts[ngram] += 1
    return dict(counts)
