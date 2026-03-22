"""Alphabet utilities for classical cryptography."""

import string
from math import gcd as _gcd

ALPHABET = string.ascii_uppercase


def clean_text(text: str) -> str:
    """Remove non-alphabetic characters and convert to uppercase."""
    return "".join(c.upper() for c in text if c.isalpha())


def char_to_num(char: str) -> int:
    """Convert a character to its numeric position (A=0, B=1, ..., Z=25)."""
    return ord(char.upper()) - ord("A")


def num_to_char(num: int) -> str:
    """Convert a numeric position to its character (0=A, 1=B, ..., 25=Z)."""
    return chr((num % 26) + ord("A"))


def gcd(a: int, b: int) -> int:
    """Compute the greatest common divisor of a and b."""
    return _gcd(a, b)


def mod_inverse(a: int, m: int) -> int:
    """
    Compute the modular multiplicative inverse of a mod m using
    the extended Euclidean algorithm.

    Raises ValueError if no inverse exists (a and m are not coprime).
    """
    a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m} (gcd={g})")
    return x % m


def _extended_gcd(a: int, b: int) -> tuple:
    """Extended Euclidean algorithm. Returns (gcd, x, y) such that ax + by = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def coprime_values(m: int = 26) -> list:
    """Return all values in [1, m) that are coprime to m."""
    return [a for a in range(1, m) if _gcd(a, m) == 1]
