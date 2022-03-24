"""
Introduction to Information Security
HW2
Encryption by B10830002
"""


import sys
import argparse


def des_encryption(key, plaintext: str) -> str:
    return "DES"


def get_parser():
    parser = argparse.ArgumentParser(
        prog="decrypt.py",
        description="decrypt ciphertext by the method and key entered by the user",
    )
    parser.add_argument("-i", "--input", help="the cyphertext to decrypt")
    parser.add_argument("-k", "--key", help="the decryption key")
    return parser


def main():
    args = get_parser().parse_args()
    print(des_encryption(args.key, args.input))


if __name__ == "__main__":
    main()
