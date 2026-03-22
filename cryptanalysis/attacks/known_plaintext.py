"""Known plaintext attacks for classical ciphers."""

import numpy as np
from ..utils.alphabet import char_to_num, mod_inverse, clean_text, gcd
from ..utils.matrix import matrix_mod, matrix_mod_inverse


def kpa_caesar(plaintext: str, ciphertext: str) -> int:
    """
    Derive the Caesar cipher key from a known plaintext-ciphertext pair.

    Only needs one corresponding letter pair.

    Args:
        plaintext: Known plaintext.
        ciphertext: Corresponding ciphertext.

    Returns:
        The key (shift value).
    """
    p_clean = clean_text(plaintext)
    c_clean = clean_text(ciphertext)

    if not p_clean or not c_clean:
        raise ValueError("Both plaintext and ciphertext must contain letters")

    p_val = char_to_num(p_clean[0])
    c_val = char_to_num(c_clean[0])

    return (c_val - p_val) % 26


def kpa_affine(plaintext: str, ciphertext: str) -> tuple:
    """
    Derive the Affine cipher key (a, b) from a known plaintext-ciphertext pair.

    Needs at least two corresponding letter pairs.
    E(x) = (a*x + b) mod 26

    Args:
        plaintext: Known plaintext (at least 2 characters).
        ciphertext: Corresponding ciphertext.

    Returns:
        Tuple (a, b) representing the Affine cipher key.

    Raises:
        ValueError: If the key cannot be determined from the given pair.
    """
    p_clean = clean_text(plaintext)
    c_clean = clean_text(ciphertext)

    if len(p_clean) < 2 or len(c_clean) < 2:
        raise ValueError("Need at least 2 character pairs")

    p1, p2 = char_to_num(p_clean[0]), char_to_num(p_clean[1])
    c1, c2 = char_to_num(c_clean[0]), char_to_num(c_clean[1])

    # c1 = a*p1 + b mod 26
    # c2 = a*p2 + b mod 26
    # c1 - c2 = a*(p1 - p2) mod 26
    delta_p = (p1 - p2) % 26
    delta_c = (c1 - c2) % 26

    if gcd(delta_p, 26) != 1:
        # Try more pairs if available
        for i in range(len(p_clean)):
            for j in range(i + 1, len(p_clean)):
                pi, pj = char_to_num(p_clean[i]), char_to_num(p_clean[j])
                ci, cj = char_to_num(c_clean[i]), char_to_num(c_clean[j])
                dp = (pi - pj) % 26
                dc = (ci - cj) % 26
                if gcd(dp, 26) == 1:
                    a = (dc * mod_inverse(dp, 26)) % 26
                    b = (ci - a * pi) % 26
                    return (a, b)
        raise ValueError(
            f"Cannot determine key: (p1-p2)={delta_p} is not coprime to 26"
        )

    a = (delta_c * mod_inverse(delta_p, 26)) % 26
    b = (c1 - a * p1) % 26

    return (a, b)


def kpa_hill(plaintext: str, ciphertext: str, key_size: int = 2) -> np.ndarray:
    """
    Recover a Hill cipher key matrix from known plaintext-ciphertext pairs.

    Args:
        plaintext: Known plaintext (at least key_size^2 characters).
        ciphertext: Corresponding ciphertext.
        key_size: Size of the key matrix (default: 2 for a 2x2 matrix).

    Returns:
        The recovered key matrix as a numpy array.

    Raises:
        ValueError: If the key cannot be recovered.
    """
    from ..ciphers.hill import HillCipher

    result = HillCipher.known_plaintext_attack(plaintext, ciphertext, key_size)
    if result is None:
        raise ValueError("Could not recover the key matrix")
    return result
