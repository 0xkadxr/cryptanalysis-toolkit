"""Matrix operations for Hill cipher and related algorithms."""

import numpy as np
from .alphabet import mod_inverse


def matrix_mod(matrix: np.ndarray, modulus: int = 26) -> np.ndarray:
    """Reduce all elements of a matrix modulo the given modulus."""
    return np.mod(matrix, modulus).astype(int)


def matrix_determinant_mod(matrix: np.ndarray, modulus: int = 26) -> int:
    """Compute the determinant of a matrix modulo the given modulus."""
    det = int(round(np.linalg.det(matrix)))
    return det % modulus


def matrix_mod_inverse(matrix: np.ndarray, modulus: int = 26) -> np.ndarray:
    """
    Compute the modular inverse of a matrix.

    The matrix must be square and its determinant must be coprime to the modulus.

    Returns:
        The inverse matrix with all elements reduced mod modulus.

    Raises:
        ValueError: If the matrix is not invertible mod the modulus.
    """
    n = matrix.shape[0]
    det = matrix_determinant_mod(matrix, modulus)

    try:
        det_inv = mod_inverse(det, modulus)
    except ValueError:
        raise ValueError(
            f"Matrix is not invertible mod {modulus} (det={det})"
        )

    # Compute the adjugate (classical adjoint) matrix
    if n == 1:
        return np.array([[det_inv]]).astype(int)

    adjugate = _adjugate_mod(matrix, modulus)
    result = matrix_mod(det_inv * adjugate, modulus)
    return result


def _adjugate_mod(matrix: np.ndarray, modulus: int) -> np.ndarray:
    """Compute the adjugate (transpose of cofactor matrix) mod modulus."""
    n = matrix.shape[0]
    cofactors = np.zeros((n, n), dtype=int)

    for i in range(n):
        for j in range(n):
            minor = _minor(matrix, i, j)
            cofactor = int(round(np.linalg.det(minor)))
            cofactors[i][j] = ((-1) ** (i + j) * cofactor) % modulus

    return cofactors.T


def _minor(matrix: np.ndarray, row: int, col: int) -> np.ndarray:
    """Return the minor matrix with the given row and column removed."""
    return np.delete(np.delete(matrix, row, axis=0), col, axis=1)
