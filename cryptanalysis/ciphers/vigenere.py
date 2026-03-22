"""Vigenere cipher implementation with automated breaking."""

from ..utils.alphabet import char_to_num, num_to_char, clean_text
from ..utils.scoring import english_score
from ..analysis.ioc import estimate_key_length_ioc
from ..analysis.frequency import letter_frequency, compare_to_english


class VigenereCipher:
    """
    Vigenere cipher: polyalphabetic substitution using a keyword.

    Each letter of the key shifts the corresponding plaintext letter.
    """

    def __init__(self, key: str):
        self.key = clean_text(key)
        if not self.key:
            raise ValueError("Key must contain at least one alphabetic character")

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using the Vigenere cipher."""
        result = []
        key_index = 0
        for char in plaintext:
            if char.isalpha():
                shift = char_to_num(self.key[key_index % len(self.key)])
                encrypted = (char_to_num(char) + shift) % 26
                new_char = num_to_char(encrypted)
                result.append(new_char if char.isupper() else new_char.lower())
                key_index += 1
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using the Vigenere cipher."""
        result = []
        key_index = 0
        for char in ciphertext:
            if char.isalpha():
                shift = char_to_num(self.key[key_index % len(self.key)])
                decrypted = (char_to_num(char) - shift) % 26
                new_char = num_to_char(decrypted)
                result.append(new_char if char.isupper() else new_char.lower())
                key_index += 1
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def find_key_length(ciphertext: str, max_length: int = 20) -> int:
        """
        Estimate the key length using Index of Coincidence analysis.

        Args:
            ciphertext: The ciphertext to analyze.
            max_length: Maximum key length to consider.

        Returns:
            The estimated key length.
        """
        cleaned = clean_text(ciphertext)
        return estimate_key_length_ioc(cleaned, max_length)

    @staticmethod
    def break_cipher(ciphertext: str, max_key_length: int = 20) -> tuple:
        """
        Attempt to fully break a Vigenere cipher.

        1. Estimate key length using IoC.
        2. For each position in the key, find the shift that produces
           the most English-like frequency distribution.

        Args:
            ciphertext: The ciphertext to break.
            max_key_length: Maximum key length to test.

        Returns:
            Tuple of (estimated_key, decrypted_text).
        """
        cleaned = clean_text(ciphertext)
        if len(cleaned) < 20:
            return _brute_force_short(ciphertext, max_key_length)

        key_length = estimate_key_length_ioc(cleaned, max_key_length)

        # For each position in the key, extract every key_length-th character
        # and find the best Caesar shift
        key = []
        for i in range(key_length):
            column = cleaned[i::key_length]
            best_shift = _find_best_shift(column)
            key.append(num_to_char(best_shift))

        key_str = "".join(key)
        cipher = VigenereCipher(key_str)
        decrypted = cipher.decrypt(ciphertext)
        return key_str, decrypted

    def __repr__(self):
        return f"VigenereCipher(key='{self.key}')"


def _find_best_shift(text: str) -> int:
    """Find the Caesar shift that makes the text most English-like."""
    best_shift = 0
    best_score = float("inf")

    from ..analysis.frequency import _load_english_freq

    expected = _load_english_freq()

    for shift in range(26):
        decrypted = ""
        for c in text:
            decrypted += num_to_char((char_to_num(c) - shift) % 26)

        # Chi-squared test against English frequencies
        freq = letter_frequency(decrypted)
        chi_sq = 0.0
        n = len(decrypted)
        for letter, exp_freq in expected.items():
            observed = freq.get(letter, 0) * n
            exp_count = exp_freq * n
            if exp_count > 0:
                chi_sq += ((observed - exp_count) ** 2) / exp_count

        if chi_sq < best_score:
            best_score = chi_sq
            best_shift = shift

    return best_shift


def _brute_force_short(ciphertext: str, max_key_length: int) -> tuple:
    """Brute force short ciphertexts by trying all key lengths 1-5."""
    best_score = -1
    best_result = ("A", ciphertext)

    for length in range(1, min(6, max_key_length + 1)):
        cleaned = clean_text(ciphertext)
        key = []
        for i in range(length):
            column = cleaned[i::length]
            best_shift = _find_best_shift(column)
            key.append(num_to_char(best_shift))
        key_str = "".join(key)
        cipher = VigenereCipher(key_str)
        decrypted = cipher.decrypt(ciphertext)
        score = english_score(decrypted)
        if score > best_score:
            best_score = score
            best_result = (key_str, decrypted)

    return best_result
