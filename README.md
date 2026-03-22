![CI](https://github.com/kadirou12333/cryptanalysis-toolkit/actions/workflows/ci.yml/badge.svg)

# Cryptanalysis Toolkit

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)

Classical cipher implementations and cryptanalysis toolkit. Encrypt, decrypt, and break historical ciphers with modern analysis techniques.

## Supported Ciphers

| Cipher | Type | Key Type | Breakable |
|--------|------|----------|-----------|
| Caesar | Monoalphabetic | Integer (0-25) | Brute force (26 keys) |
| Affine | Monoalphabetic | Two integers (a, b) | Brute force (312 keys) |
| Vigenere | Polyalphabetic | Keyword string | Kasiski + IoC + frequency |
| Playfair | Digraph | Keyword string | Manual / hill climbing |
| Hill | Polygraphic | Matrix (n x n) | Known plaintext attack |
| Transposition | Transposition | Keyword / column order | Brute force (small keys) |
| Substitution | Monoalphabetic | 26-char permutation | Frequency analysis |

## Quick Start

### Installation

```bash
git clone https://github.com/kadirou12333/cryptanalysis-toolkit.git
cd cryptanalysis-toolkit
pip install -r requirements.txt
```

### Basic Usage

```python
from cryptanalysis.ciphers import CaesarCipher, VigenereCipher

# Caesar cipher
caesar = CaesarCipher(key=3)
encrypted = caesar.encrypt("HELLO WORLD")   # "KHOOR ZRUOG"
decrypted = caesar.decrypt("KHOOR ZRUOG")   # "HELLO WORLD"

# Vigenere cipher
vig = VigenereCipher(key="SECRET")
encrypted = vig.encrypt("ATTACK AT DAWN")
decrypted = vig.decrypt(encrypted)
```

### Breaking Ciphers

```python
from cryptanalysis.ciphers import CaesarCipher, VigenereCipher

# Break Caesar cipher (brute force)
results = CaesarCipher.brute_force("KHOOR ZRUOG")
key, plaintext, score = results[0]  # Best match

# Break Vigenere cipher (automated)
key, plaintext = VigenereCipher.break_cipher(ciphertext)
```

## CLI Usage

```bash
# Encrypt
python cli.py encrypt caesar --key 3 --text "HELLO WORLD"
python cli.py encrypt vigenere --key SECRET --text "ATTACK AT DAWN"
python cli.py encrypt affine --key "5,8" --text "HELLO WORLD"

# Decrypt
python cli.py decrypt caesar --key 3 --text "KHOOR ZRUOG"
python cli.py decrypt vigenere --key SECRET --text "SLKEEG EX HEWB"

# Analyze
python cli.py analyze frequency --text "some text to analyze"
python cli.py analyze ioc --text "some ciphertext"
python cli.py analyze ngram --text "some text" --n 3

# Break ciphers
python cli.py break caesar --text "KHOOR ZRUOG"
python cli.py break vigenere --text "long ciphertext here"
python cli.py break affine --text "RCLLA OAPLX"
```

## Analysis Tools

### Frequency Analysis
Compute letter and bigram frequencies, compare against English distribution using chi-squared testing, and generate frequency plots.

```python
from cryptanalysis.analysis.frequency import letter_frequency, compare_to_english

freq = letter_frequency(ciphertext)
chi_sq = compare_to_english(freq)
```

### Index of Coincidence (IoC)
Measure the probability of two random letters matching. Used to distinguish monoalphabetic from polyalphabetic ciphers and to estimate Vigenere key lengths.

```python
from cryptanalysis.analysis.ioc import index_of_coincidence, estimate_key_length_ioc

ioc = index_of_coincidence(ciphertext)   # English ~0.0667
key_len = estimate_key_length_ioc(ciphertext, max_length=20)
```

### Kasiski Examination
Find repeated sequences in Vigenere ciphertext to estimate key length via GCD of spacings.

```python
from cryptanalysis.analysis.kasiski import estimate_key_length

key_len = estimate_key_length(ciphertext)
```

### N-gram Analysis
Analyze character n-grams to identify patterns in ciphertext.

```python
from cryptanalysis.analysis.ngram import top_ngrams

bigrams = top_ngrams(text, n=2, top_k=10)
trigrams = top_ngrams(text, n=3, top_k=10)
```

## Attack Methods

### Brute Force Attacks
Exhaustively try all possible keys for ciphers with small key spaces.

### Known Plaintext Attacks
Recover keys when you have matching plaintext-ciphertext pairs. Supports Caesar, Affine, and Hill ciphers.

### Frequency-Based Attacks
Map ciphertext letter frequencies to expected English frequencies to break monoalphabetic substitution ciphers.

### Dictionary Attacks
Try common English words as Vigenere keys.

## How Classical Ciphers Work

**Caesar Cipher**: Each letter is shifted by a fixed number of positions in the alphabet. With only 26 possible keys, it is trivially broken by brute force.

**Affine Cipher**: Applies a linear function E(x) = (ax + b) mod 26 to each letter. The value 'a' must be coprime to 26, giving 312 possible key pairs.

**Vigenere Cipher**: Uses a keyword to apply different Caesar shifts to different positions. Broken by first estimating the key length (via IoC or Kasiski), then solving each position independently.

**Playfair Cipher**: Encrypts pairs of letters using a 5x5 grid derived from a keyword. Significantly harder to break than simple substitution.

**Hill Cipher**: Uses matrix multiplication mod 26 to encrypt blocks of letters. Vulnerable to known plaintext attacks via matrix inversion.

**Columnar Transposition**: Rearranges letters by writing them in rows and reading off columns in a specified order. The message content is preserved but reordered.

## Running Tests

```bash
pytest tests/ -v
```

## Project Structure

```
cryptanalysis-toolkit/
├── cryptanalysis/          # Main package
│   ├── ciphers/            # Cipher implementations
│   ├── analysis/           # Analysis tools
│   ├── attacks/            # Attack methods
│   ├── utils/              # Utilities
│   └── data/               # Reference data
├── cli.py                  # Command-line interface
├── examples/               # Usage examples
└── tests/                  # Test suite
```

## References

- Singh, S. (1999). *The Code Book*. Anchor Books.
- Stinson, D. R. (2005). *Cryptography: Theory and Practice*. Chapman & Hall/CRC.
- Schneier, B. (1996). *Applied Cryptography*. Wiley.
- Friedman, W. F. (1922). *The Index of Coincidence and Its Applications in Cryptanalysis*.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
