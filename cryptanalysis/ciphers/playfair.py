"""Playfair cipher implementation."""

from ..utils.alphabet import clean_text


class PlayfairCipher:
    """
    Playfair cipher: digraph substitution using a 5x5 key matrix.

    Letters I and J are treated as the same letter.
    """

    def __init__(self, key: str):
        self.key = clean_text(key)
        self.matrix = self._generate_matrix()
        self.pos = {}  # letter -> (row, col)
        for r in range(5):
            for c in range(5):
                self.pos[self.matrix[r][c]] = (r, c)

    def _generate_matrix(self) -> list:
        """Generate the 5x5 Playfair key matrix."""
        seen = set()
        matrix_chars = []

        # Add key characters first (replace J with I)
        for char in self.key:
            c = char.upper()
            if c == "J":
                c = "I"
            if c not in seen and c.isalpha():
                seen.add(c)
                matrix_chars.append(c)

        # Fill remaining with unused letters
        for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":  # no J
            if c not in seen:
                seen.add(c)
                matrix_chars.append(c)

        # Build 5x5 matrix
        matrix = []
        for i in range(0, 25, 5):
            matrix.append(matrix_chars[i : i + 5])
        return matrix

    def _prepare_text(self, text: str) -> list:
        """
        Prepare text for Playfair encryption.

        - Replace J with I
        - Split into digraphs
        - Insert X between repeated letters in a pair
        - Pad with X if odd length
        """
        cleaned = clean_text(text).replace("J", "I")
        pairs = []
        i = 0
        while i < len(cleaned):
            a = cleaned[i]
            if i + 1 < len(cleaned):
                b = cleaned[i + 1]
                if a == b:
                    pairs.append((a, "X"))
                    i += 1
                else:
                    pairs.append((a, b))
                    i += 2
            else:
                pairs.append((a, "X"))
                i += 1
        return pairs

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using the Playfair cipher."""
        pairs = self._prepare_text(plaintext)
        result = []

        for a, b in pairs:
            r1, c1 = self.pos[a]
            r2, c2 = self.pos[b]

            if r1 == r2:
                # Same row: shift right
                result.append(self.matrix[r1][(c1 + 1) % 5])
                result.append(self.matrix[r2][(c2 + 1) % 5])
            elif c1 == c2:
                # Same column: shift down
                result.append(self.matrix[(r1 + 1) % 5][c1])
                result.append(self.matrix[(r2 + 1) % 5][c2])
            else:
                # Rectangle: swap columns
                result.append(self.matrix[r1][c2])
                result.append(self.matrix[r2][c1])

        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using the Playfair cipher."""
        cleaned = clean_text(ciphertext).replace("J", "I")
        if len(cleaned) % 2 != 0:
            cleaned += "X"

        pairs = [(cleaned[i], cleaned[i + 1]) for i in range(0, len(cleaned), 2)]
        result = []

        for a, b in pairs:
            r1, c1 = self.pos[a]
            r2, c2 = self.pos[b]

            if r1 == r2:
                # Same row: shift left
                result.append(self.matrix[r1][(c1 - 1) % 5])
                result.append(self.matrix[r2][(c2 - 1) % 5])
            elif c1 == c2:
                # Same column: shift up
                result.append(self.matrix[(r1 - 1) % 5][c1])
                result.append(self.matrix[(r2 - 1) % 5][c2])
            else:
                # Rectangle: swap columns
                result.append(self.matrix[r1][c2])
                result.append(self.matrix[r2][c1])

        return "".join(result)

    def get_matrix(self) -> list:
        """Return the 5x5 key matrix."""
        return [row[:] for row in self.matrix]

    def __repr__(self):
        return f"PlayfairCipher(key='{self.key}')"
