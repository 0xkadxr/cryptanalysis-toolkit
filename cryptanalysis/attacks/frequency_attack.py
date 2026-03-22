"""Frequency-based attacks for breaking substitution ciphers."""

from ..analysis.frequency import letter_frequency, _load_english_freq
from ..utils.alphabet import ALPHABET


def frequency_attack_substitution(ciphertext: str) -> tuple:
    """
    Attempt to break a monoalphabetic substitution cipher using frequency analysis.

    Maps the most frequent ciphertext letters to the most frequent English letters.
    This produces an approximate solution that often needs manual refinement.

    Args:
        ciphertext: The ciphertext to break.

    Returns:
        Tuple of (mapping, decrypted_text) where mapping is a dict
        of ciphertext->plaintext letter substitutions.
    """
    # Get ciphertext letter frequencies
    ct_freq = letter_frequency(ciphertext)
    ct_sorted = sorted(ct_freq.items(), key=lambda x: x[1], reverse=True)

    # Get English letter frequencies sorted by frequency
    eng_freq = _load_english_freq()
    eng_sorted = sorted(eng_freq.items(), key=lambda x: x[1], reverse=True)

    # Map most frequent ciphertext letter to most frequent English letter
    mapping = {}
    for i, (ct_letter, _) in enumerate(ct_sorted):
        if i < len(eng_sorted):
            mapping[ct_letter.upper()] = eng_sorted[i][0].upper()

    # Fill in any unmapped letters
    used_plain = set(mapping.values())
    unmapped_ct = [c for c in ALPHABET if c not in mapping]
    available_plain = [c for c in ALPHABET if c not in used_plain]

    for ct, pt in zip(unmapped_ct, available_plain):
        mapping[ct] = pt

    # Apply mapping to decrypt
    result = []
    for char in ciphertext:
        if char.isalpha():
            mapped = mapping.get(char.upper(), char.upper())
            result.append(mapped if char.isupper() else mapped.lower())
        else:
            result.append(char)

    return mapping, "".join(result)
