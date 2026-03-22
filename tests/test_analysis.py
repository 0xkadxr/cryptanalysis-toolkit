"""Tests for analysis and cryptanalysis tools."""

import pytest
from cryptanalysis.analysis.frequency import (
    letter_frequency,
    bigram_frequency,
    compare_to_english,
    frequency_table,
)
from cryptanalysis.analysis.ioc import (
    index_of_coincidence,
    expected_ioc,
    estimate_key_length_ioc,
)
from cryptanalysis.analysis.kasiski import (
    find_repeated_sequences,
    find_spacings,
    estimate_key_length,
)
from cryptanalysis.analysis.ngram import ngram_frequency, top_ngrams
from cryptanalysis.ciphers import VigenereCipher
from cryptanalysis.attacks.known_plaintext import kpa_caesar, kpa_affine


# ===================== Frequency Analysis Tests =====================

class TestFrequencyAnalysis:
    def test_letter_frequency_simple(self):
        freq = letter_frequency("AABB")
        assert freq["a"] == 0.5
        assert freq["b"] == 0.5

    def test_letter_frequency_case_insensitive(self):
        freq = letter_frequency("AaAa")
        assert freq["a"] == 1.0

    def test_letter_frequency_ignores_non_alpha(self):
        freq = letter_frequency("A1B2C3")
        assert abs(freq["a"] - 1 / 3) < 0.001
        assert "1" not in freq

    def test_letter_frequency_empty(self):
        assert letter_frequency("") == {}
        assert letter_frequency("123") == {}

    def test_bigram_frequency(self):
        freq = bigram_frequency("ABAB")
        assert "ab" in freq
        assert "ba" in freq

    def test_compare_to_english(self):
        # Text with English-like distribution should have lower chi-squared
        english_text = "the quick brown fox jumps over the lazy dog"
        random_text = "xzqjv kpwm fgthy nlrbc"

        freq_english = letter_frequency(english_text)
        freq_random = letter_frequency(random_text)

        chi_english = compare_to_english(freq_english)
        chi_random = compare_to_english(freq_random)

        # English text should be closer to expected distribution
        assert chi_english < chi_random

    def test_frequency_table(self):
        table = frequency_table("AAABBC")
        assert table[0][0] == "a"  # 'a' is most frequent
        assert table[0][1] == 3  # count is 3


# ===================== IoC Tests =====================

class TestIndexOfCoincidence:
    def test_ioc_uniform(self):
        # All same letter: IoC = 1.0
        text = "AAAAAAAAAA"
        ioc = index_of_coincidence(text)
        assert abs(ioc - 1.0) < 0.001

    def test_ioc_english_range(self):
        # Longer English text should have IoC closer to 0.0667
        text = (
            "TO BE OR NOT TO BE THAT IS THE QUESTION WHETHER IT IS NOBLER "
            "IN THE MIND TO SUFFER THE SLINGS AND ARROWS OF OUTRAGEOUS FORTUNE "
            "OR TO TAKE ARMS AGAINST A SEA OF TROUBLES AND BY OPPOSING END THEM"
        )
        ioc = index_of_coincidence(text)
        assert 0.05 < ioc < 0.09  # reasonable range for English text

    def test_ioc_empty(self):
        assert index_of_coincidence("") == 0.0

    def test_ioc_single_char(self):
        assert index_of_coincidence("A") == 0.0

    def test_expected_ioc(self):
        # Key length 1 should give English IoC
        assert abs(expected_ioc(1) - 0.0667) < 0.001

    def test_estimate_key_length(self):
        # Encrypt with known key and try to recover length
        # Need substantial text for reliable key length estimation
        plaintext = (
            "CRYPTOGRAPHY IS THE PRACTICE AND STUDY OF TECHNIQUES FOR SECURE "
            "COMMUNICATION IN THE PRESENCE OF ADVERSARIAL BEHAVIOR THE FIELD "
            "HAS EXPANDED BEYOND JUST ENCRYPTION TO INCLUDE AUTHENTICATION "
            "AND INTEGRITY CHECKING AMONG OTHER SECURITY PROPERTIES MODERN "
            "CRYPTOGRAPHY EXISTS AT THE INTERSECTION OF THE DISCIPLINES OF "
            "MATHEMATICS COMPUTER SCIENCE ELECTRICAL ENGINEERING AND PHYSICS "
            "APPLICATIONS OF CRYPTOGRAPHY INCLUDE ELECTRONIC COMMERCE CHIP "
            "BASED PAYMENT CARDS DIGITAL CURRENCIES COMPUTER PASSWORDS AND "
            "MILITARY COMMUNICATIONS"
        )
        cipher = VigenereCipher("SECRET")  # key length = 6
        ciphertext = cipher.encrypt(plaintext)
        from cryptanalysis.utils.alphabet import clean_text

        estimated = estimate_key_length_ioc(clean_text(ciphertext), max_length=10)
        # Should estimate 6 or a factor thereof (2, 3, 6)
        assert estimated in [2, 3, 6]


# ===================== Kasiski Tests =====================

class TestKasiski:
    def test_find_repeated_sequences(self):
        # Text with deliberate repeats
        text = "ABCDEFABCGHIABCJKL"
        repeated = find_repeated_sequences(text, min_length=3)
        assert "ABC" in repeated
        assert len(repeated["ABC"]) == 3

    def test_find_spacings(self):
        text = "ABCDEFABCGHIABCJKL"
        spacings = find_spacings(text, min_length=3)
        assert len(spacings) > 0
        # ABC appears at 0, 6, 12 - spacings should include 6 and 12
        assert 6 in spacings

    def test_estimate_key_length_basic(self):
        # With spacings of 6 and 12, GCD should be 6
        text = "ABCDEFABCGHIABCJKL"
        length = estimate_key_length(text, min_length=3)
        assert length in [2, 3, 6]  # factors of 6


# ===================== N-gram Tests =====================

class TestNgram:
    def test_bigram_frequency(self):
        freq = ngram_frequency("HELLO", n=2)
        assert "he" in freq
        assert "el" in freq
        assert "ll" in freq
        assert "lo" in freq

    def test_trigram_frequency(self):
        freq = ngram_frequency("HELLO", n=3)
        assert "hel" in freq

    def test_top_ngrams(self):
        results = top_ngrams("AABABCABCD", n=2, top_k=3)
        assert len(results) <= 3
        # "ab" should be the most frequent bigram
        assert results[0][0] == "ab"

    def test_empty_text(self):
        assert ngram_frequency("", n=2) == {}
        assert ngram_frequency("A", n=2) == {}


# ===================== Known Plaintext Attack Tests =====================

class TestKnownPlaintextAttacks:
    def test_kpa_caesar(self):
        from cryptanalysis.ciphers import CaesarCipher

        cipher = CaesarCipher(7)
        plaintext = "HELLO"
        ciphertext = cipher.encrypt(plaintext)
        key = kpa_caesar(plaintext, ciphertext)
        assert key == 7

    def test_kpa_affine(self):
        from cryptanalysis.ciphers import AffineCipher

        cipher = AffineCipher(5, 8)
        plaintext = "HELLO"
        ciphertext = cipher.encrypt(plaintext)
        a, b = kpa_affine(plaintext, ciphertext)
        assert a == 5
        assert b == 8
