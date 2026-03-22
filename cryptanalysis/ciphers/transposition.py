"""Columnar transposition cipher implementation."""

import itertools
from ..utils.scoring import english_score


class TranspositionCipher:
    """
    Columnar transposition cipher.

    The key defines the order in which columns are read off.
    The key can be a string (alphabetical ordering) or a list of integers.
    """

    def __init__(self, key):
        """
        Initialize the transposition cipher.

        Args:
            key: Either a string (columns ordered alphabetically by key letters)
                 or a list of integers defining column order (0-indexed).
        """
        if isinstance(key, str):
            self.key_str = key.upper()
            self.order = self._key_to_order(self.key_str)
        elif isinstance(key, (list, tuple)):
            self.order = list(key)
            self.key_str = None
        else:
            raise ValueError("Key must be a string or list of integers")

        self.num_cols = len(self.order)

    @staticmethod
    def _key_to_order(key: str) -> list:
        """Convert a keyword to column ordering based on alphabetical order."""
        indexed = sorted(enumerate(key), key=lambda x: x[1])
        order = [0] * len(key)
        for rank, (original_idx, _) in enumerate(indexed):
            order[original_idx] = rank
        return order

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext using columnar transposition.

        Non-alphabetic characters are preserved by first extracting them,
        encrypting only alphabetic characters, then reinserting.
        """
        # Work with all characters but only transpose alpha
        text = plaintext.upper()
        alpha_only = [c for c in text if c.isalpha()]

        # Pad to fill last row
        num_rows = -(-len(alpha_only) // self.num_cols)  # ceiling division
        while len(alpha_only) < num_rows * self.num_cols:
            alpha_only.append("X")

        # Fill grid row by row
        grid = []
        for r in range(num_rows):
            row = alpha_only[r * self.num_cols : (r + 1) * self.num_cols]
            grid.append(row)

        # Read off columns in key order
        result = []
        for col_rank in range(self.num_cols):
            col_idx = self.order.index(col_rank)
            for row in grid:
                result.append(row[col_idx])

        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using columnar transposition."""
        text = ciphertext.upper()
        alpha_only = [c for c in text if c.isalpha()]
        n = len(alpha_only)
        num_rows = -(-n // self.num_cols)

        # Calculate column lengths (handle incomplete last row)
        full_cols = n - (num_rows - 1) * self.num_cols
        col_lengths = []
        for col_rank in range(self.num_cols):
            col_idx = self.order.index(col_rank)
            if col_idx < full_cols or num_rows * self.num_cols == n:
                col_lengths.append(num_rows)
            else:
                col_lengths.append(num_rows - 1)

        # Fill columns in key order
        columns = {}
        pos = 0
        for col_rank in range(self.num_cols):
            col_idx = self.order.index(col_rank)
            length = col_lengths[col_rank]
            columns[col_idx] = list(alpha_only[pos : pos + length])
            pos += length

        # Read off row by row
        result = []
        for r in range(num_rows):
            for c in range(self.num_cols):
                if r < len(columns.get(c, [])):
                    result.append(columns[c][r])

        return "".join(result)

    @staticmethod
    def brute_force(ciphertext: str, max_key_length: int = 6) -> list:
        """
        Try all column orderings up to max_key_length and return results
        sorted by English score.

        Warning: This is O(n!) per key length, so keep max_key_length small.

        Returns:
            List of (key_order, decrypted_text, score) tuples, best first.
        """
        results = []
        for length in range(2, max_key_length + 1):
            for perm in itertools.permutations(range(length)):
                cipher = TranspositionCipher(list(perm))
                try:
                    decrypted = cipher.decrypt(ciphertext)
                    score = english_score(decrypted)
                    results.append((list(perm), decrypted, score))
                except Exception:
                    continue

        results.sort(key=lambda x: x[2], reverse=True)
        return results

    def __repr__(self):
        if self.key_str:
            return f"TranspositionCipher(key='{self.key_str}')"
        return f"TranspositionCipher(key={self.order})"
