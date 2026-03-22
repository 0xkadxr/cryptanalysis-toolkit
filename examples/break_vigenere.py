#!/usr/bin/env python3
"""Example: Breaking a Vigenere cipher using IoC and frequency analysis."""

from cryptanalysis.ciphers import VigenereCipher
from cryptanalysis.analysis.ioc import index_of_coincidence, estimate_key_length_ioc
from cryptanalysis.analysis.kasiski import estimate_key_length
from cryptanalysis.utils.alphabet import clean_text


def main():
    # Encrypt with a known key
    key = "CIPHER"
    plaintext = (
        "CRYPTOGRAPHY IS THE PRACTICE AND STUDY OF TECHNIQUES FOR SECURE "
        "COMMUNICATION IN THE PRESENCE OF ADVERSARIAL BEHAVIOR THE FIELD "
        "HAS EXPANDED BEYOND JUST ENCRYPTION TO INCLUDE AUTHENTICATION "
        "AND INTEGRITY CHECKING AMONG OTHER SECURITY PROPERTIES"
    )
    cipher = VigenereCipher(key)
    ciphertext = cipher.encrypt(plaintext)

    print("Vigenere Cipher Breaking Demo")
    print("=" * 60)
    print(f"Key used: {key} (length={len(key)})")
    print(f"Ciphertext: {ciphertext[:80]}...\n")

    # Step 1: Measure IoC
    cleaned = clean_text(ciphertext)
    ioc = index_of_coincidence(cleaned)
    print(f"Step 1: Index of Coincidence = {ioc:.6f}")
    print(f"  (English ~0.0667, Random ~0.0385)")
    print(f"  This suggests polyalphabetic encryption.\n")

    # Step 2: Estimate key length with IoC
    est_length_ioc = estimate_key_length_ioc(cleaned, max_length=15)
    print(f"Step 2: Key length estimate (IoC method) = {est_length_ioc}")

    # Step 3: Estimate key length with Kasiski
    est_length_kasiski = estimate_key_length(cleaned, min_length=3, max_key=15)
    print(f"Step 3: Key length estimate (Kasiski method) = {est_length_kasiski}\n")

    # Step 4: Full automated break
    print("Step 4: Automated cipher breaking")
    print("-" * 40)
    recovered_key, decrypted = VigenereCipher.break_cipher(ciphertext)
    print(f"  Recovered key: {recovered_key}")
    print(f"  Decrypted: {decrypted[:80]}...")

    # Verify
    if recovered_key == key:
        print(f"\n  Key recovered correctly!")
    else:
        print(f"\n  Note: Recovered key '{recovered_key}' differs from actual key '{key}'")


if __name__ == "__main__":
    main()
