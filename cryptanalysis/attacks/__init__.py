"""Attack methods for breaking classical ciphers."""

from .brute_force import brute_force_caesar, brute_force_affine, brute_force_transposition
from .known_plaintext import kpa_caesar, kpa_affine, kpa_hill
from .frequency_attack import frequency_attack_substitution
from .dictionary import dictionary_attack_caesar, dictionary_attack_vigenere

__all__ = [
    "brute_force_caesar",
    "brute_force_affine",
    "brute_force_transposition",
    "kpa_caesar",
    "kpa_affine",
    "kpa_hill",
    "frequency_attack_substitution",
    "dictionary_attack_caesar",
    "dictionary_attack_vigenere",
]
