"""Affine cipher implementation."""

from ..utils.alphabet import char_to_num, num_to_char, mod_inverse, gcd, coprime_values
from ..utils.scoring import english_score


class AffineCipher:
    """
    Affine cipher: E(x) = (a*x + b) mod 26, D(x) = a_inv * (x - b) mod 26.

    The value 'a' must be coprime to 26.
    """

    def __init__(self, a: int, b: int):
        if gcd(a % 26, 26) != 1:
            raise ValueError(
                f"'a' ({a}) must be coprime to 26. "
                f"Valid values: {coprime_values(26)}"
            )
        self.a = a % 26
        self.b = b % 26
        self.a_inv = mod_inverse(self.a, 26)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using the Affine cipher."""
        result = []
        for char in plaintext:
            if char.isalpha():
                x = char_to_num(char)
                encrypted = (self.a * x + self.b) % 26
                new_char = num_to_char(encrypted)
                result.append(new_char if char.isupper() else new_char.lower())
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using the Affine cipher."""
        result = []
        for char in ciphertext:
            if char.isalpha():
                y = char_to_num(char)
                decrypted = (self.a_inv * (y - self.b)) % 26
                new_char = num_to_char(decrypted)
                result.append(new_char if char.isupper() else new_char.lower())
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def brute_force(ciphertext: str) -> list:
        """
        Try all valid (a, b) pairs and return decryptions sorted by English score.

        Returns:
            List of ((a, b), decrypted_text, score) tuples, best first.
        """
        results = []
        valid_a = coprime_values(26)
        for a in valid_a:
            for b in range(26):
                cipher = AffineCipher(a, b)
                decrypted = cipher.decrypt(ciphertext)
                score = english_score(decrypted)
                results.append(((a, b), decrypted, score))
        results.sort(key=lambda x: x[2], reverse=True)
        return results

    def __repr__(self):
        return f"AffineCipher(a={self.a}, b={self.b})"
