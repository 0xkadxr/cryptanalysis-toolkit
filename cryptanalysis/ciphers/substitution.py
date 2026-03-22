"""General monoalphabetic substitution cipher implementation."""

import random
import string
from ..utils.alphabet import ALPHABET


class SubstitutionCipher:
    """
    General monoalphabetic substitution cipher.

    Each letter in the alphabet is replaced by a different letter
    according to a substitution key (a permutation of the alphabet).
    """

    def __init__(self, key: str = None):
        """
        Initialize the substitution cipher.

        Args:
            key: A 26-character string representing the substitution alphabet.
                 key[0] is the replacement for 'A', key[1] for 'B', etc.
                 If None, a random key is generated.
        """
        if key is None:
            letters = list(ALPHABET)
            random.shuffle(letters)
            self.key = "".join(letters)
        else:
            self.key = key.upper()

        if len(self.key) != 26:
            raise ValueError("Key must be exactly 26 characters")
        if len(set(self.key)) != 26:
            raise ValueError("Key must be a permutation of the alphabet")
        for c in self.key:
            if c not in ALPHABET:
                raise ValueError(f"Key contains invalid character: {c}")

        # Build reverse mapping for decryption
        self.reverse_key = [""] * 26
        for i, c in enumerate(self.key):
            self.reverse_key[ord(c) - ord("A")] = chr(i + ord("A"))
        self.reverse_key = "".join(self.reverse_key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using the substitution cipher."""
        result = []
        for char in plaintext:
            if char.isalpha():
                idx = ord(char.upper()) - ord("A")
                new_char = self.key[idx]
                result.append(new_char if char.isupper() else new_char.lower())
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using the substitution cipher."""
        result = []
        for char in ciphertext:
            if char.isalpha():
                idx = ord(char.upper()) - ord("A")
                new_char = self.reverse_key[idx]
                result.append(new_char if char.isupper() else new_char.lower())
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def from_mapping(mapping: dict) -> "SubstitutionCipher":
        """
        Create a SubstitutionCipher from a letter mapping dictionary.

        Args:
            mapping: Dict mapping plaintext letters to ciphertext letters.
                     e.g., {'A': 'Z', 'B': 'Y', ...}
        """
        key = []
        for c in ALPHABET:
            if c in mapping:
                key.append(mapping[c].upper())
            else:
                key.append(c)
        return SubstitutionCipher("".join(key))

    def get_mapping(self) -> dict:
        """Return the substitution mapping as a dictionary."""
        return {chr(i + ord("A")): self.key[i] for i in range(26)}

    def __repr__(self):
        return f"SubstitutionCipher(key='{self.key}')"
