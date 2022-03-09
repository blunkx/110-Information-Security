# Introduction to Information Security
# HW1
# Decryption B10830002
import click
import sys
from pathlib import Path


def read_file(file_name) -> str:
    file_path = Path(__file__).parent.resolve() / file_name
    print(file_path)
    try:
        with open(file_path) as input_file:
            return input_file.read()
    except Exception:
        print("Failed to open!")
        sys.exit()


def write_file(file_name: str, text: str) -> None:
    file_path = Path(__file__).parent.resolve() / file_name
    try:
        with open(file_path, "w") as out:
            out.write(text)
    except Exception:
        print("Failed to open!")
        sys.exit()


def caesar(shift: int, plaintext: str) -> str:
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    digit = "0123456789"
    ciphertext = ""
    for i in plaintext:
        if str.isupper(i):
            ciphertext += upper[(upper.index(i) + shift) % 26]
        elif str.islower(i):
            ciphertext += lower[(lower.index(i) + shift) % 26]
        elif str.isdigit(i):
            ciphertext += digit[(digit.index(i) + shift) % 10]
        else:
            ciphertext += i
    return ciphertext


def playfair(key: int, ciphertext: str) -> str:
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper_table = []
    lower_table = []
    plaintext = ""
    print()


def vernam():
    print()


def railfence():
    print()


def row():
    print()


@click.command()
@click.option("-m", "--method", "method", required=True, help="The decryption method")
@click.option(
    "-i",
    "--input",
    "input",
    default="ciphertext",
    required=True,
    help="The name of the input file",
)
@click.option("-k", "--key", "key", required=True, help="The decryption key")
def main(method, input, key):
    print(method)
    print(input)
    print(key)


if __name__ == "__main__":
    main()
