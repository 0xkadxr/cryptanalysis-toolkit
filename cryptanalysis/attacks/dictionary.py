"""Dictionary-based attacks for classical ciphers."""

from ..ciphers.caesar import CaesarCipher
from ..ciphers.vigenere import VigenereCipher
from ..utils.scoring import english_score, _load_english_words


def dictionary_attack_caesar(ciphertext: str) -> list:
    """
    Attack a Caesar cipher by checking which shifts produce the most
    recognizable English words.

    Args:
        ciphertext: The ciphertext to break.

    Returns:
        List of (key, decrypted_text, word_count) tuples, sorted by word count.
    """
    words = _load_english_words()
    results = []

    for key in range(26):
        cipher = CaesarCipher(key)
        decrypted = cipher.decrypt(ciphertext)

        # Count how many words from the decrypted text are English words
        decrypted_words = decrypted.lower().split()
        match_count = sum(
            1 for w in decrypted_words
            if w.strip(".,!?;:'-\"()").lower() in words
        )
        results.append((key, decrypted, match_count))

    results.sort(key=lambda x: x[2], reverse=True)
    return results


def dictionary_attack_vigenere(
    ciphertext: str, key_words: list = None, max_key_length: int = 10
) -> list:
    """
    Attack a Vigenere cipher by trying common English words as keys.

    Args:
        ciphertext: The ciphertext to break.
        key_words: Optional list of words to try as keys.
                   If None, uses common English words up to max_key_length.
        max_key_length: Maximum key word length to try.

    Returns:
        List of (key, decrypted_text, score) tuples, sorted by score.
    """
    if key_words is None:
        all_words = _load_english_words()
        key_words = [w for w in all_words if 2 <= len(w) <= max_key_length]

    results = []
    for word in key_words:
        if not word.isalpha():
            continue
        try:
            cipher = VigenereCipher(word)
            decrypted = cipher.decrypt(ciphertext)
            score = english_score(decrypted)
            results.append((word.upper(), decrypted, score))
        except ValueError:
            continue

    results.sort(key=lambda x: x[2], reverse=True)
    return results
