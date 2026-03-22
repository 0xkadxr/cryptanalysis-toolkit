#!/usr/bin/env python3
"""Example: Analyzing text with frequency analysis and n-gram tools."""

from cryptanalysis.analysis.frequency import (
    letter_frequency,
    bigram_frequency,
    compare_to_english,
    frequency_table,
)
from cryptanalysis.analysis.ioc import index_of_coincidence
from cryptanalysis.analysis.ngram import top_ngrams


def main():
    # Sample English text
    text = (
        "It was the best of times it was the worst of times it was the age "
        "of wisdom it was the age of foolishness it was the epoch of belief "
        "it was the epoch of incredulity it was the season of light it was "
        "the season of darkness"
    )

    print("Text Analysis Demo")
    print("=" * 60)
    print(f"Text: {text[:80]}...\n")

    # Letter frequency
    print("Letter Frequency Analysis")
    print("-" * 40)
    table = frequency_table(text)
    for letter, count, freq in table[:10]:
        bar = "#" * int(freq * 100)
        print(f"  {letter.upper()}: {count:3d} ({freq:.4f}) {bar}")
    print(f"  ... and {len(table) - 10} more letters\n")

    # Compare to English
    freq = letter_frequency(text)
    chi_sq = compare_to_english(freq)
    print(f"Chi-squared vs English: {chi_sq:.4f}")
    print(f"  (Lower = more English-like)\n")

    # Index of Coincidence
    ioc = index_of_coincidence(text)
    print(f"Index of Coincidence: {ioc:.6f}")
    print(f"  English expected:   0.0667")
    print(f"  Random expected:    0.0385\n")

    # Top bigrams
    print("Top 10 Bigrams")
    print("-" * 40)
    bigrams = top_ngrams(text, n=2, top_k=10)
    for ngram, freq in bigrams:
        print(f"  {ngram.upper()}: {freq:.4f}")

    # Top trigrams
    print("\nTop 10 Trigrams")
    print("-" * 40)
    trigrams = top_ngrams(text, n=3, top_k=10)
    for ngram, freq in trigrams:
        print(f"  {ngram.upper()}: {freq:.4f}")


if __name__ == "__main__":
    main()
