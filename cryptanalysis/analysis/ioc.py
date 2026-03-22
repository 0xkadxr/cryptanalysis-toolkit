"""Index of Coincidence analysis for cryptanalysis."""

from collections import Counter
from ..utils.alphabet import clean_text


# Expected IoC for English text
ENGLISH_IOC = 0.0667

# Expected IoC for random text (uniform distribution)
RANDOM_IOC = 1.0 / 26  # ~0.0385


def index_of_coincidence(text: str) -> float:
    """
    Calculate the Index of Coincidence (IoC) of a text.

    The IoC measures the probability that two randomly chosen letters
    from the text are the same. English text has IoC ~0.0667, while
    random text has IoC ~0.0385.

    Args:
        text: Input text (only alphabetic characters are used).

    Returns:
        The IoC value (float).
    """
    cleaned = clean_text(text)
    n = len(cleaned)
    if n <= 1:
        return 0.0

    counts = Counter(cleaned)
    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = n * (n - 1)

    return numerator / denominator


def expected_ioc(key_length: int) -> float:
    """
    Calculate the expected IoC for a Vigenere cipher with a given key length.

    For a key of length L, the expected IoC is approximately:
    (1/L) * ENGLISH_IOC + ((L-1)/L) * RANDOM_IOC

    Args:
        key_length: The key length.

    Returns:
        Expected IoC value.
    """
    if key_length <= 0:
        return RANDOM_IOC
    return (1.0 / key_length) * ENGLISH_IOC + ((key_length - 1.0) / key_length) * RANDOM_IOC


def estimate_key_length_ioc(ciphertext: str, max_length: int = 20) -> int:
    """
    Estimate the Vigenere key length by testing different key lengths
    and comparing the average IoC of the resulting columns to the
    expected English IoC.

    Args:
        ciphertext: The ciphertext to analyze.
        max_length: Maximum key length to test.

    Returns:
        The estimated key length.
    """
    cleaned = clean_text(ciphertext)

    if len(cleaned) < 20:
        return 1

    best_length = 1
    best_score = float("inf")

    for length in range(1, min(max_length + 1, len(cleaned) // 2)):
        # Split ciphertext into 'length' columns
        columns = [cleaned[i::length] for i in range(length)]

        # Calculate average IoC across columns
        avg_ioc = sum(index_of_coincidence(col) for col in columns) / length

        # The best key length produces columns with IoC closest to English
        distance = abs(avg_ioc - ENGLISH_IOC)
        if distance < best_score:
            best_score = distance
            best_length = length

    return best_length
