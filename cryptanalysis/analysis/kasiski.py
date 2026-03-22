"""Kasiski examination for breaking Vigenere ciphers."""

from collections import defaultdict
from math import gcd
from functools import reduce
from ..utils.alphabet import clean_text


def find_repeated_sequences(ciphertext: str, min_length: int = 3) -> dict:
    """
    Find all repeated sequences in the ciphertext.

    Args:
        ciphertext: The ciphertext to analyze.
        min_length: Minimum sequence length to look for (default: 3).

    Returns:
        Dictionary mapping sequences to lists of starting positions.
    """
    cleaned = clean_text(ciphertext)
    sequences = defaultdict(list)

    for length in range(min_length, min(len(cleaned) // 2, 20) + 1):
        for i in range(len(cleaned) - length + 1):
            seq = cleaned[i : i + length]
            sequences[seq].append(i)

    # Only keep sequences that appear more than once
    return {seq: positions for seq, positions in sequences.items() if len(positions) > 1}


def find_spacings(ciphertext: str, min_length: int = 3) -> list:
    """
    Find the distances between repeated sequences in the ciphertext.

    Args:
        ciphertext: The ciphertext to analyze.
        min_length: Minimum sequence length (default: 3).

    Returns:
        List of all spacings (distances) found.
    """
    repeated = find_repeated_sequences(ciphertext, min_length)
    spacings = []

    for seq, positions in repeated.items():
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                spacing = positions[j] - positions[i]
                spacings.append(spacing)

    return spacings


def estimate_key_length(ciphertext: str, min_length: int = 3, max_key: int = 20) -> int:
    """
    Estimate the Vigenere key length using the Kasiski examination.

    Finds repeated sequences, computes their spacings, and returns
    the most common GCD of the spacings.

    Args:
        ciphertext: The ciphertext to analyze.
        min_length: Minimum sequence length for repeats.
        max_key: Maximum key length to consider.

    Returns:
        Estimated key length (integer >= 2).
    """
    spacings = find_spacings(ciphertext, min_length)

    if not spacings:
        return 3  # default fallback

    # Count GCD factors
    factor_counts = defaultdict(int)
    for spacing in spacings:
        for factor in range(2, min(spacing + 1, max_key + 1)):
            if spacing % factor == 0:
                factor_counts[factor] += 1

    if not factor_counts:
        return 3

    # Return the most common factor
    best = max(factor_counts.items(), key=lambda x: x[1])
    return best[0]
