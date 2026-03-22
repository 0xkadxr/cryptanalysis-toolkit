"""Caesar cipher implementation."""

from ..utils.alphabet import char_to_num, num_to_char
from ..utils.scoring import english_score


class CaesarCipher:
    """
    Caesar cipher: shifts each letter by a fixed number of positions.

    E(x) = (x + key) mod 26
    D(x) = (x - key) mod 26
    """

    def __init__(self, key: int = 3):
        self.key = key % 26

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using the Caesar cipher.

        Non-alphabetic characters are preserved in place.
        """
        result = []
        for char in plaintext:
            if char.isalpha():
                shifted = (char_to_num(char) + self.key) % 26
                new_char = num_to_char(shifted)
                result.append(new_char if char.isupper() else new_char.lower())
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt ciphertext using the Caesar cipher.

        Non-alphabetic characters are preserved in place.
        """
        result = []
        for char in ciphertext:
            if char.isalpha():
                shifted = (char_to_num(char) - self.key) % 26
                new_char = num_to_char(shifted)
                result.append(new_char if char.isupper() else new_char.lower())
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def brute_force(ciphertext: str) -> list:
        """
        Try all 26 possible keys and return decryptions sorted by English score.

        Returns:
            List of (key, decrypted_text, score) tuples, best first.
        """
        results = []
        for key in range(26):
            cipher = CaesarCipher(key)
            decrypted = cipher.decrypt(ciphertext)
            score = english_score(decrypted)
            results.append((key, decrypted, score))
        results.sort(key=lambda x: x[2], reverse=True)
        return results

    def __repr__(self):
        return f"CaesarCipher(key={self.key})"
