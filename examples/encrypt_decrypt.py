#!/usr/bin/env python3
"""Examples of encrypting and decrypting with various classical ciphers."""

from cryptanalysis.ciphers import (
    CaesarCipher,
    AffineCipher,
    VigenereCipher,
    PlayfairCipher,
    HillCipher,
    TranspositionCipher,
    SubstitutionCipher,
)


def main():
    plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    print(f"Original: {plaintext}\n")

    # Caesar Cipher
    print("=" * 50)
    print("Caesar Cipher (key=3)")
    caesar = CaesarCipher(3)
    encrypted = caesar.encrypt(plaintext)
    decrypted = caesar.decrypt(encrypted)
    print(f"  Encrypted: {encrypted}")
    print(f"  Decrypted: {decrypted}")

    # Affine Cipher
    print("\n" + "=" * 50)
    print("Affine Cipher (a=5, b=8)")
    affine = AffineCipher(5, 8)
    encrypted = affine.encrypt(plaintext)
    decrypted = affine.decrypt(encrypted)
    print(f"  Encrypted: {encrypted}")
    print(f"  Decrypted: {decrypted}")

    # Vigenere Cipher
    print("\n" + "=" * 50)
    print("Vigenere Cipher (key='SECRET')")
    vigenere = VigenereCipher("SECRET")
    encrypted = vigenere.encrypt(plaintext)
    decrypted = vigenere.decrypt(encrypted)
    print(f"  Encrypted: {encrypted}")
    print(f"  Decrypted: {decrypted}")

    # Playfair Cipher
    print("\n" + "=" * 50)
    print("Playfair Cipher (key='MONARCHY')")
    playfair = PlayfairCipher("MONARCHY")
    encrypted = playfair.encrypt(plaintext)
    decrypted = playfair.decrypt(encrypted)
    print(f"  Encrypted: {encrypted}")
    print(f"  Decrypted: {decrypted}")

    # Hill Cipher
    print("\n" + "=" * 50)
    print("Hill Cipher (2x2 key matrix)")
    hill = HillCipher([[3, 3], [2, 5]])
    encrypted = hill.encrypt("HELP")
    decrypted = hill.decrypt(encrypted)
    print(f"  Encrypted: {encrypted}")
    print(f"  Decrypted: {decrypted}")

    # Transposition Cipher
    print("\n" + "=" * 50)
    print("Transposition Cipher (key='ZEBRA')")
    trans = TranspositionCipher("ZEBRA")
    encrypted = trans.encrypt(plaintext)
    decrypted = trans.decrypt(encrypted)
    print(f"  Encrypted: {encrypted}")
    print(f"  Decrypted: {decrypted}")

    # Substitution Cipher
    print("\n" + "=" * 50)
    print("Substitution Cipher (Atbash)")
    key = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
    sub = SubstitutionCipher(key)
    encrypted = sub.encrypt(plaintext)
    decrypted = sub.decrypt(encrypted)
    print(f"  Encrypted: {encrypted}")
    print(f"  Decrypted: {decrypted}")


if __name__ == "__main__":
    main()
