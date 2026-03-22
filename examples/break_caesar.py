#!/usr/bin/env python3
"""Example: Breaking a Caesar cipher using brute force and frequency analysis."""

from cryptanalysis.ciphers import CaesarCipher
from cryptanalysis.attacks.brute_force import brute_force_caesar
from cryptanalysis.attacks.known_plaintext import kpa_caesar


def main():
    # Encrypt a message with an unknown key
    secret_key = 17
    plaintext = "THE ART OF WAR TEACHES US NOT TO RELY ON THE LIKELIHOOD OF THE ENEMY NOT COMING"
    cipher = CaesarCipher(secret_key)
    ciphertext = cipher.encrypt(plaintext)

    print("Caesar Cipher Breaking Demo")
    print("=" * 60)
    print(f"Ciphertext: {ciphertext}\n")

    # Method 1: Brute force with scoring
    print("Method 1: Brute Force Attack")
    print("-" * 40)
    results = brute_force_caesar(ciphertext, top_n=3)
    for i, (key, decrypted, score) in enumerate(results):
        marker = " <-- BEST" if i == 0 else ""
        print(f"  Key {key:2d} (score: {score:6.1f}): {decrypted[:60]}...{marker}")

    print(f"\nRecovered key: {results[0][0]} (actual: {secret_key})")

    # Method 2: Known plaintext attack
    print("\n\nMethod 2: Known Plaintext Attack")
    print("-" * 40)
    known_plain = "THE"
    known_cipher = ciphertext[:3]
    recovered_key = kpa_caesar(known_plain, known_cipher)
    print(f"  Known plaintext: '{known_plain}' -> '{known_cipher}'")
    print(f"  Recovered key: {recovered_key}")

    # Verify
    recovered_cipher = CaesarCipher(recovered_key)
    print(f"  Decrypted: {recovered_cipher.decrypt(ciphertext)}")


if __name__ == "__main__":
    main()
