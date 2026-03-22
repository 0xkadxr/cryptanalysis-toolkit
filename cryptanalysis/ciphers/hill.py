"""Hill cipher implementation using matrix operations."""

import numpy as np
from ..utils.alphabet import char_to_num, num_to_char, clean_text
from ..utils.matrix import matrix_mod, matrix_mod_inverse, matrix_determinant_mod


class HillCipher:
    """
    Hill cipher: encrypts blocks of text using matrix multiplication mod 26.

    E(P) = K * P mod 26
    D(C) = K_inv * C mod 26
    """

    def __init__(self, key_matrix):
        """
        Initialize the Hill cipher with a key matrix.

        Args:
            key_matrix: A square matrix (list of lists or numpy array).
                        Must be invertible mod 26.
        """
        self.key = np.array(key_matrix, dtype=int)
        if self.key.ndim != 2 or self.key.shape[0] != self.key.shape[1]:
            raise ValueError("Key matrix must be square")
        self.n = self.key.shape[0]

        # Validate invertibility
        det = matrix_determinant_mod(self.key, 26)
        from ..utils.alphabet import gcd

        if gcd(det, 26) != 1:
            raise ValueError(
                f"Key matrix is not invertible mod 26 (det={det}). "
                "Determinant must be coprime to 26."
            )

        self.key_inv = matrix_mod_inverse(self.key, 26)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using the Hill cipher.

        Text is cleaned and padded with 'X' to fill the last block.
        """
        cleaned = clean_text(plaintext)
        # Pad to multiple of n
        while len(cleaned) % self.n != 0:
            cleaned += "X"

        result = []
        for i in range(0, len(cleaned), self.n):
            block = np.array(
                [char_to_num(c) for c in cleaned[i : i + self.n]], dtype=int
            )
            encrypted_block = matrix_mod(self.key @ block, 26)
            result.extend(num_to_char(x) for x in encrypted_block)

        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using the Hill cipher."""
        cleaned = clean_text(ciphertext)
        if len(cleaned) % self.n != 0:
            raise ValueError(
                f"Ciphertext length must be a multiple of {self.n}"
            )

        result = []
        for i in range(0, len(cleaned), self.n):
            block = np.array(
                [char_to_num(c) for c in cleaned[i : i + self.n]], dtype=int
            )
            decrypted_block = matrix_mod(self.key_inv @ block, 26)
            result.extend(num_to_char(x) for x in decrypted_block)

        return "".join(result)

    @staticmethod
    def known_plaintext_attack(plaintext: str, ciphertext: str, key_size: int = 2):
        """
        Recover the key matrix using a known plaintext-ciphertext pair.

        Requires at least key_size plaintext-ciphertext character pairs.

        Args:
            plaintext: Known plaintext (at least key_size * key_size characters).
            ciphertext: Corresponding ciphertext.
            key_size: Size of the key matrix (default: 2x2).

        Returns:
            The recovered key matrix as a numpy array, or None if recovery fails.
        """
        p_clean = clean_text(plaintext)
        c_clean = clean_text(ciphertext)

        needed = key_size * key_size
        if len(p_clean) < needed or len(c_clean) < needed:
            raise ValueError(
                f"Need at least {needed} characters for a {key_size}x{key_size} key"
            )

        # Build plaintext and ciphertext matrices
        # Each column is a block of key_size characters
        P = np.zeros((key_size, key_size), dtype=int)
        C = np.zeros((key_size, key_size), dtype=int)

        for col in range(key_size):
            for row in range(key_size):
                idx = col * key_size + row
                P[row][col] = char_to_num(p_clean[idx])
                C[row][col] = char_to_num(c_clean[idx])

        # K * P = C mod 26  =>  K = C * P_inv mod 26
        try:
            P_inv = matrix_mod_inverse(P, 26)
            K = matrix_mod(C @ P_inv, 26)
            return K
        except ValueError:
            return None

    def __repr__(self):
        return f"HillCipher(key_matrix={self.key.tolist()})"
