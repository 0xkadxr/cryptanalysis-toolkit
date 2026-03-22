"""Brute force attack implementations for classical ciphers."""

import itertools
from ..ciphers.caesar import CaesarCipher
from ..ciphers.affine import AffineCipher
from ..ciphers.transposition import TranspositionCipher
from ..utils.scoring import english_score


def brute_force_caesar(ciphertext: str, top_n: int = 5) -> list:
    """
    Brute force a Caesar cipher by trying all 26 shifts.

    Results are scored by English likelihood.

    Args:
        ciphertext: The ciphertext to break.
        top_n: Number of top results to return.

    Returns:
        List of (key, decrypted_text, score) tuples, best first.
    """
    results = CaesarCipher.brute_force(ciphertext)
    return results[:top_n]


def brute_force_affine(ciphertext: str, top_n: int = 5) -> list:
    """
    Brute force an Affine cipher by trying all valid (a, b) pairs.

    There are 12 valid values for 'a' and 26 for 'b', giving 312 combinations.

    Args:
        ciphertext: The ciphertext to break.
        top_n: Number of top results to return.

    Returns:
        List of ((a, b), decrypted_text, score) tuples, best first.
    """
    results = AffineCipher.brute_force(ciphertext)
    return results[:top_n]


def brute_force_transposition(ciphertext: str, max_cols: int = 6, top_n: int = 5) -> list:
    """
    Brute force a columnar transposition cipher by trying all column orderings.

    Warning: The number of permutations grows factorially with max_cols.
    max_cols=6 means up to 720 permutations per length; max_cols=7 is 5040.

    Args:
        ciphertext: The ciphertext to break.
        max_cols: Maximum number of columns to try.
        top_n: Number of top results to return.

    Returns:
        List of (key_order, decrypted_text, score) tuples, best first.
    """
    results = TranspositionCipher.brute_force(ciphertext, max_cols)
    return results[:top_n]
