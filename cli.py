#!/usr/bin/env python3
"""
Interactive CLI for the Cryptanalysis Toolkit.

Usage:
    python cli.py encrypt caesar --key 3 --text "HELLO WORLD"
    python cli.py decrypt vigenere --key "SECRET" --text "ZINNO PGVNU"
    python cli.py analyze frequency --text "some text to analyze"
    python cli.py break caesar --text "KHOOR ZRUOG"
    python cli.py break vigenere --text "..."
"""

import argparse
import sys

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from cryptanalysis.ciphers import (
    CaesarCipher,
    AffineCipher,
    VigenereCipher,
    PlayfairCipher,
    HillCipher,
    TranspositionCipher,
    SubstitutionCipher,
)
from cryptanalysis.analysis.frequency import letter_frequency, frequency_table, compare_to_english
from cryptanalysis.analysis.ioc import index_of_coincidence
from cryptanalysis.analysis.ngram import top_ngrams
from cryptanalysis.attacks.brute_force import brute_force_caesar, brute_force_affine
from cryptanalysis.attacks.dictionary import dictionary_attack_vigenere

console = Console() if RICH_AVAILABLE else None


def print_output(text: str, style: str = None):
    """Print with rich if available, otherwise plain."""
    if console and style:
        console.print(text, style=style)
    elif console:
        console.print(text)
    else:
        print(text)


def cmd_encrypt(args):
    """Handle encrypt command."""
    cipher_map = {
        "caesar": lambda: CaesarCipher(int(args.key)),
        "affine": lambda: AffineCipher(*map(int, args.key.split(","))),
        "vigenere": lambda: VigenereCipher(args.key),
        "playfair": lambda: PlayfairCipher(args.key),
        "transposition": lambda: TranspositionCipher(args.key),
    }

    cipher_name = args.cipher.lower()
    if cipher_name not in cipher_map:
        print_output(f"Unknown cipher: {cipher_name}", "bold red")
        return

    try:
        cipher = cipher_map[cipher_name]()
        result = cipher.encrypt(args.text)

        if console:
            panel = Panel(result, title="Encrypted Text", border_style="green")
            console.print(panel)
        else:
            print(f"Encrypted: {result}")
    except Exception as e:
        print_output(f"Error: {e}", "bold red")


def cmd_decrypt(args):
    """Handle decrypt command."""
    cipher_map = {
        "caesar": lambda: CaesarCipher(int(args.key)),
        "affine": lambda: AffineCipher(*map(int, args.key.split(","))),
        "vigenere": lambda: VigenereCipher(args.key),
        "playfair": lambda: PlayfairCipher(args.key),
        "transposition": lambda: TranspositionCipher(args.key),
    }

    cipher_name = args.cipher.lower()
    if cipher_name not in cipher_map:
        print_output(f"Unknown cipher: {cipher_name}", "bold red")
        return

    try:
        cipher = cipher_map[cipher_name]()
        result = cipher.decrypt(args.text)

        if console:
            panel = Panel(result, title="Decrypted Text", border_style="blue")
            console.print(panel)
        else:
            print(f"Decrypted: {result}")
    except Exception as e:
        print_output(f"Error: {e}", "bold red")


def cmd_analyze(args):
    """Handle analyze command."""
    analysis_type = args.analysis_type.lower()
    text = args.text

    if analysis_type == "frequency":
        table_data = frequency_table(text)
        chi_sq = compare_to_english(letter_frequency(text))

        if console:
            table = Table(title="Letter Frequency Analysis", box=box.ROUNDED)
            table.add_column("Letter", style="cyan", justify="center")
            table.add_column("Count", justify="right")
            table.add_column("Frequency", justify="right")
            for letter, count, freq in table_data:
                table.add_row(letter.upper(), str(count), f"{freq:.4f}")
            console.print(table)
            console.print(f"\nChi-squared vs English: [bold]{chi_sq:.2f}[/bold]")
            if chi_sq < 0.05:
                console.print("Interpretation: Very close to English", style="green")
            elif chi_sq < 0.15:
                console.print("Interpretation: Likely English or simple substitution", style="yellow")
            else:
                console.print("Interpretation: Significantly different from English", style="red")
        else:
            print("Letter Frequency Analysis:")
            for letter, count, freq in table_data:
                bar = "#" * int(freq * 100)
                print(f"  {letter.upper()}: {count:4d} ({freq:.4f}) {bar}")
            print(f"\nChi-squared vs English: {chi_sq:.2f}")

    elif analysis_type == "ioc":
        ioc = index_of_coincidence(text)
        if console:
            console.print(f"Index of Coincidence: [bold cyan]{ioc:.6f}[/bold cyan]")
            console.print(f"English expected:     [dim]0.0667[/dim]")
            console.print(f"Random expected:      [dim]0.0385[/dim]")
        else:
            print(f"Index of Coincidence: {ioc:.6f}")
            print(f"English expected:     0.0667")
            print(f"Random expected:      0.0385")

    elif analysis_type == "ngram":
        n = getattr(args, "n", 2)
        results = top_ngrams(text, n=n, top_k=20)

        if console:
            table = Table(title=f"Top {n}-grams", box=box.ROUNDED)
            table.add_column("N-gram", style="cyan")
            table.add_column("Frequency", justify="right")
            for ngram, freq in results:
                table.add_row(ngram.upper(), f"{freq:.4f}")
            console.print(table)
        else:
            print(f"Top {n}-grams:")
            for ngram, freq in results:
                print(f"  {ngram.upper()}: {freq:.4f}")
    else:
        print_output(f"Unknown analysis type: {analysis_type}", "bold red")


def cmd_break(args):
    """Handle break command."""
    cipher_name = args.cipher.lower()
    text = args.text

    if cipher_name == "caesar":
        results = brute_force_caesar(text, top_n=5)

        if console:
            table = Table(title="Caesar Cipher Brute Force", box=box.ROUNDED)
            table.add_column("Key", style="cyan", justify="center")
            table.add_column("Score", justify="right")
            table.add_column("Decrypted Text", style="green")
            for key, decrypted, score in results:
                table.add_row(str(key), f"{score:.1f}", decrypted[:80])
            console.print(table)
            console.print(f"\n[bold green]Best guess: key={results[0][0]}[/bold green]")
        else:
            print("Caesar Cipher Brute Force Results:")
            for key, decrypted, score in results:
                print(f"  Key {key:2d} (score: {score:.1f}): {decrypted[:80]}")

    elif cipher_name == "affine":
        results = brute_force_affine(text, top_n=5)

        if console:
            table = Table(title="Affine Cipher Brute Force", box=box.ROUNDED)
            table.add_column("Key (a,b)", style="cyan", justify="center")
            table.add_column("Score", justify="right")
            table.add_column("Decrypted Text", style="green")
            for (a, b), decrypted, score in results:
                table.add_row(f"({a},{b})", f"{score:.1f}", decrypted[:80])
            console.print(table)
        else:
            print("Affine Cipher Brute Force Results:")
            for (a, b), decrypted, score in results:
                print(f"  Key ({a},{b}) (score: {score:.1f}): {decrypted[:80]}")

    elif cipher_name == "vigenere":
        key, decrypted = VigenereCipher.break_cipher(text)

        if console:
            console.print(Panel(
                f"[bold cyan]Estimated Key:[/bold cyan] {key}\n\n"
                f"[bold green]Decrypted Text:[/bold green]\n{decrypted}",
                title="Vigenere Cipher Break",
                border_style="yellow",
            ))
        else:
            print(f"Estimated Key: {key}")
            print(f"Decrypted: {decrypted}")
    else:
        print_output(f"Breaking {cipher_name} is not yet supported via CLI", "bold yellow")


def main():
    parser = argparse.ArgumentParser(
        description="Cryptanalysis Toolkit - Classical Cipher Tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py encrypt caesar --key 3 --text "HELLO WORLD"
  python cli.py decrypt vigenere --key SECRET --text "ZINNO PGVNU"
  python cli.py analyze frequency --text "some text here"
  python cli.py analyze ioc --text "some text here"
  python cli.py break caesar --text "KHOOR ZRUOG"
  python cli.py break vigenere --text "encrypted text here"
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Encrypt
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt text")
    encrypt_parser.add_argument("cipher", help="Cipher to use (caesar, affine, vigenere, playfair, transposition)")
    encrypt_parser.add_argument("--key", required=True, help="Encryption key")
    encrypt_parser.add_argument("--text", required=True, help="Text to encrypt")

    # Decrypt
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt text")
    decrypt_parser.add_argument("cipher", help="Cipher to use")
    decrypt_parser.add_argument("--key", required=True, help="Decryption key")
    decrypt_parser.add_argument("--text", required=True, help="Text to decrypt")

    # Analyze
    analyze_parser = subparsers.add_parser("analyze", help="Analyze text")
    analyze_parser.add_argument("analysis_type", help="Analysis type (frequency, ioc, ngram)")
    analyze_parser.add_argument("--text", required=True, help="Text to analyze")
    analyze_parser.add_argument("--n", type=int, default=2, help="N-gram size (for ngram analysis)")

    # Break
    break_parser = subparsers.add_parser("break", help="Break a cipher")
    break_parser.add_argument("cipher", help="Cipher to break (caesar, affine, vigenere)")
    break_parser.add_argument("--text", required=True, help="Ciphertext to break")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if console:
        console.print(
            Panel(
                "[bold]Cryptanalysis Toolkit[/bold] - Classical Cipher Tools",
                style="bold blue",
            )
        )

    commands = {
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "analyze": cmd_analyze,
        "break": cmd_break,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
