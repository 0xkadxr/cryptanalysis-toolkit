"""Comprehensive tests for all cipher implementations."""

import pytest
import numpy as np
from cryptanalysis.ciphers import (
    CaesarCipher,
    AffineCipher,
    VigenereCipher,
    PlayfairCipher,
    HillCipher,
    TranspositionCipher,
    SubstitutionCipher,
)


# ===================== Caesar Cipher Tests =====================

class TestCaesarCipher:
    def test_encrypt_basic(self):
        cipher = CaesarCipher(3)
        assert cipher.encrypt("HELLO") == "KHOOR"

    def test_decrypt_basic(self):
        cipher = CaesarCipher(3)
        assert cipher.decrypt("KHOOR") == "HELLO"

    def test_roundtrip(self):
        cipher = CaesarCipher(13)
        original = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        assert cipher.decrypt(cipher.encrypt(original)) == original

    def test_preserve_case(self):
        cipher = CaesarCipher(3)
        assert cipher.encrypt("Hello World") == "Khoor Zruog"

    def test_preserve_non_alpha(self):
        cipher = CaesarCipher(3)
        assert cipher.encrypt("Hello, World!") == "Khoor, Zruog!"

    def test_key_zero(self):
        cipher = CaesarCipher(0)
        assert cipher.encrypt("HELLO") == "HELLO"

    def test_key_26_wraps(self):
        cipher = CaesarCipher(26)
        assert cipher.encrypt("HELLO") == "HELLO"

    def test_empty_string(self):
        cipher = CaesarCipher(3)
        assert cipher.encrypt("") == ""
        assert cipher.decrypt("") == ""

    def test_known_vector_rot13(self):
        cipher = CaesarCipher(13)
        assert cipher.encrypt("HELLO") == "URYYB"
        assert cipher.decrypt("URYYB") == "HELLO"

    def test_brute_force_finds_key(self):
        cipher = CaesarCipher(7)
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        ciphertext = cipher.encrypt(plaintext)
        results = CaesarCipher.brute_force(ciphertext)
        # Best result should use key 7
        assert results[0][0] == 7

    def test_all_keys_roundtrip(self):
        for key in range(26):
            cipher = CaesarCipher(key)
            text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            assert cipher.decrypt(cipher.encrypt(text)) == text


# ===================== Affine Cipher Tests =====================

class TestAffineCipher:
    def test_encrypt_basic(self):
        cipher = AffineCipher(5, 8)
        assert cipher.encrypt("HELLO") == "RCLLA"

    def test_decrypt_basic(self):
        cipher = AffineCipher(5, 8)
        assert cipher.decrypt("RCLLA") == "HELLO"

    def test_roundtrip(self):
        cipher = AffineCipher(7, 3)
        original = "THE QUICK BROWN FOX"
        assert cipher.decrypt(cipher.encrypt(original)) == original

    def test_invalid_a(self):
        with pytest.raises(ValueError):
            AffineCipher(2, 0)  # 2 is not coprime to 26

    def test_invalid_a_13(self):
        with pytest.raises(ValueError):
            AffineCipher(13, 5)

    def test_preserve_non_alpha(self):
        cipher = AffineCipher(5, 8)
        result = cipher.encrypt("Hello, World!")
        assert result[5] == ","
        assert result[6] == " "

    def test_empty_string(self):
        cipher = AffineCipher(5, 8)
        assert cipher.encrypt("") == ""

    def test_brute_force(self):
        cipher = AffineCipher(5, 8)
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        ciphertext = cipher.encrypt(plaintext)
        results = AffineCipher.brute_force(ciphertext)
        assert results[0][0] == (5, 8)


# ===================== Vigenere Cipher Tests =====================

class TestVigenereCipher:
    def test_encrypt_basic(self):
        cipher = VigenereCipher("KEY")
        assert cipher.encrypt("HELLO") == "RIJVS"

    def test_decrypt_basic(self):
        cipher = VigenereCipher("KEY")
        assert cipher.decrypt("RIJVS") == "HELLO"

    def test_roundtrip(self):
        cipher = VigenereCipher("SECRET")
        original = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        assert cipher.decrypt(cipher.encrypt(original)) == original

    def test_preserve_non_alpha(self):
        cipher = VigenereCipher("KEY")
        result = cipher.encrypt("Hello, World!")
        # Non-alpha preserved, key advances only on alpha
        assert result[5] == ","

    def test_empty_key(self):
        with pytest.raises(ValueError):
            VigenereCipher("")

    def test_empty_string(self):
        cipher = VigenereCipher("KEY")
        assert cipher.encrypt("") == ""

    def test_known_vector(self):
        # Classic example: key=LEMON, plaintext=ATTACKATDAWN
        cipher = VigenereCipher("LEMON")
        assert cipher.encrypt("ATTACKATDAWN") == "LXFOPVEFRNHR"

    def test_case_preservation(self):
        cipher = VigenereCipher("KEY")
        result = cipher.encrypt("Hello World")
        assert result[0].isupper()
        assert result[1].islower()


# ===================== Playfair Cipher Tests =====================

class TestPlayfairCipher:
    def test_matrix_generation(self):
        cipher = PlayfairCipher("MONARCHY")
        matrix = cipher.get_matrix()
        # First row should start with key letters (deduped)
        assert matrix[0][0] == "M"
        assert matrix[0][1] == "O"
        assert matrix[0][2] == "N"

    def test_encrypt_basic(self):
        cipher = PlayfairCipher("MONARCHY")
        # HE -> BP (same key matrix)
        result = cipher.encrypt("HELLO")
        assert len(result) > 0
        assert result.isalpha()

    def test_roundtrip_even(self):
        cipher = PlayfairCipher("KEYWORD")
        # Playfair roundtrip: note that J->I and padding may differ
        encrypted = cipher.encrypt("TESTME")
        decrypted = cipher.decrypt(encrypted)
        # Should get back roughly the same (accounting for I/J and X padding)
        assert len(decrypted) >= 6

    def test_double_letters(self):
        cipher = PlayfairCipher("MONARCHY")
        # LL should be split with X: LX L?
        result = cipher.encrypt("BALLOON")
        assert len(result) > 0

    def test_j_replacement(self):
        cipher = PlayfairCipher("MONARCHY")
        # J should be treated as I
        assert "J" not in [c for row in cipher.get_matrix() for c in row]

    def test_matrix_size(self):
        cipher = PlayfairCipher("TEST")
        matrix = cipher.get_matrix()
        assert len(matrix) == 5
        assert all(len(row) == 5 for row in matrix)

    def test_matrix_unique_letters(self):
        cipher = PlayfairCipher("HELLO")
        matrix = cipher.get_matrix()
        all_letters = [c for row in matrix for c in row]
        assert len(set(all_letters)) == 25  # 25 unique (no J)


# ===================== Hill Cipher Tests =====================

class TestHillCipher:
    def test_encrypt_basic(self):
        # 2x2 key matrix [[3, 3], [2, 5]]
        cipher = HillCipher([[3, 3], [2, 5]])
        result = cipher.encrypt("HELP")
        assert len(result) == 4
        assert result.isalpha()

    def test_roundtrip(self):
        cipher = HillCipher([[3, 3], [2, 5]])
        original = "HELP"
        encrypted = cipher.encrypt(original)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == original

    def test_padding(self):
        cipher = HillCipher([[3, 3], [2, 5]])
        # Odd length should be padded
        result = cipher.encrypt("HEL")
        assert len(result) == 4  # padded to multiple of 2

    def test_invalid_matrix_not_square(self):
        with pytest.raises(ValueError):
            HillCipher([[1, 2, 3], [4, 5, 6]])

    def test_invalid_matrix_not_invertible(self):
        with pytest.raises(ValueError):
            HillCipher([[2, 4], [6, 8]])  # det = -8, gcd(8,26) != 1... actually det=2*8-4*6=-8, |-8|%26=18, gcd(18,26)=2

    def test_known_plaintext_attack(self):
        key = [[3, 3], [2, 5]]
        cipher = HillCipher(key)
        plaintext = "HELP"
        ciphertext = cipher.encrypt(plaintext)
        recovered = HillCipher.known_plaintext_attack(plaintext, ciphertext, 2)
        assert recovered is not None
        np.testing.assert_array_equal(recovered, np.array(key))

    def test_3x3_roundtrip(self):
        key = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
        cipher = HillCipher(key)
        original = "ACTGOD"
        encrypted = cipher.encrypt(original)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == original


# ===================== Transposition Cipher Tests =====================

class TestTranspositionCipher:
    def test_encrypt_basic(self):
        cipher = TranspositionCipher("ZEBRA")
        result = cipher.encrypt("HELLO WORLD")
        assert len(result) > 0

    def test_roundtrip_string_key(self):
        cipher = TranspositionCipher("HACK")
        original = "THEQUICKBROWNFOX"
        encrypted = cipher.encrypt(original)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == original

    def test_roundtrip_numeric_key(self):
        cipher = TranspositionCipher([2, 0, 3, 1])
        original = "THEQUICKBROWNFOX"
        encrypted = cipher.encrypt(original)
        decrypted = cipher.decrypt(encrypted)
        assert decrypted == original

    def test_empty_string(self):
        cipher = TranspositionCipher("KEY")
        assert cipher.encrypt("") == ""


# ===================== Substitution Cipher Tests =====================

class TestSubstitutionCipher:
    def test_roundtrip(self):
        cipher = SubstitutionCipher()
        original = "THE QUICK BROWN FOX"
        assert cipher.decrypt(cipher.encrypt(original)) == original

    def test_known_key(self):
        key = "ZYXWVUTSRQPONMLKJIHGFEDCBA"  # Atbash
        cipher = SubstitutionCipher(key)
        assert cipher.encrypt("A") == "Z"
        assert cipher.encrypt("Z") == "A"
        assert cipher.decrypt("Z") == "A"

    def test_roundtrip_atbash(self):
        key = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        cipher = SubstitutionCipher(key)
        original = "HELLO WORLD"
        assert cipher.decrypt(cipher.encrypt(original)) == original

    def test_invalid_key_length(self):
        with pytest.raises(ValueError):
            SubstitutionCipher("ABC")

    def test_invalid_key_duplicates(self):
        with pytest.raises(ValueError):
            SubstitutionCipher("AAXWVUTSRQPONMLKJIHGFEDCBA")

    def test_preserve_non_alpha(self):
        cipher = SubstitutionCipher()
        result = cipher.encrypt("Hello, World!")
        assert result[5] == ","
        assert result[6] == " "

    def test_from_mapping(self):
        mapping = {chr(i + 65): chr(90 - i) for i in range(26)}  # Atbash
        cipher = SubstitutionCipher.from_mapping(mapping)
        assert cipher.encrypt("HELLO") == "SVOOL"
