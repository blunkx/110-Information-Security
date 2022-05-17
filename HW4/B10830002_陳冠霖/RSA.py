#!/usr/bin/env python3
"""
Introduction to Information Security
HW4 RSA by B10830002
"""
import secrets
import argparse
import random
import math
import base64


def square_and_multiply(x: int, h: int, n=None) -> int:
    """
    square and multiply
    Args:
        x(int): Base
        h(int): Exponent
        n(int): Modulus(Optional)
    Returns:
        y(int): x^h or x^h mod n when n is given
    """
    h = bin(h)[2:]
    y = x
    for i in h[1:]:
        y *= y
        if i == "1":
            y = y * x
        if n:
            y %= n
    return y


def Miller_Rabin_primality_test(n: int, times: int) -> bool:
    """
    Check whether the number is a prime number or not.
    Args:
        n(int): Test if n is prime.
        times(int): How many times the Miller Rabin test will be performed.
    Returns:
        (bool): if return True, n is a probable prime number, otherwise it's not.
    """
    if n == 2:
        return True
    elif n % 2 == 0:
        return False
    # n-1 = 2^k * m
    n1 = n - 1
    k = 0
    m = n1
    while m % 2 == 0:
        m //= 2
        k += 1
    a = [random.randrange(2, n - 2) for i in range(times)]
    for it in a:
        b = square_and_multiply(it, m, n)
        if b != 1 and b != n1:
            i = 1
            while i < k and b != n1:
                b = square_and_multiply(b, 2, n)
                if b == 1:
                    return False
                i += 1
            if b != n1:
                return False
    return True


def prime_num_gen(nbytes: int) -> int:
    """
    Generate random number until it's a prime number.
    Using the Miller-Rabin Primality Test to check if a random number is prime.
    Args:
        nbytes(int): The length of random number.
    Returns:
        prime_num(int): A prime number that passes robin miller test ten times.
    """
    while True:
        prime_num = secrets.token_hex(nbytes)
        prime_num = int(prime_num, 16)
        if Miller_Rabin_primality_test(prime_num, 10):
            break
    return prime_num


def rsa_key_gen():
    """
    Key generation for RSA
    Args:
        None
    Returns:
        rsa_key(dict): A dict contain RSA key pairs, including p, q, n, phi_n, e, d.
    """

    def print_key(var_name: str, val: str) -> dict:
        print("{} = {}\n".format(var_name, val))

    rsa_key = {}
    rsa_key["p"] = prime_num_gen(64)
    rsa_key["q"] = prime_num_gen(64)
    rsa_key["n"] = rsa_key["p"] * rsa_key["q"]
    rsa_key["phi_n"] = (rsa_key["p"] - 1) * (rsa_key["q"] - 1)
    while True:
        e = random.randrange(1, rsa_key["phi_n"] - 1)
        if math.gcd(e, rsa_key["phi_n"]) == 1:
            rsa_key["e"] = e
            break
    rsa_key["d"] = pow(e, -1, rsa_key["phi_n"])
    for key in rsa_key:
        print_key(key, rsa_key[key])
    return rsa_key


def str_to_base64(inp: str) -> str:
    """
    Convert a string to a base64 encoded string.
    Args:
        inp(str): A string to be encoded.
    Returns:
        (str): A base64 encoded string.
    """
    return base64.b64encode(bytes.fromhex(inp)).decode()


def base64_to_str(inp: str) -> str:
    """
    Convert a base64 encoded string to a string.
    Args:
        inp(str): A base64 encoded string.

    Returns:
        (str): An ascii string.
    """
    return base64.b64decode(inp.encode()).hex()


def rsa_encryption(plaintext: str, n: int, e: int) -> str:
    """
    RSA encryption.
    Args:
        plaintext(str): The plaintext to be encrypted.
        n(int): Modulus.
        e(int): Public exponent.
    Returns:
        (str): A base64 encoded string encrypted by RSA.
    """
    plaintext = [ord(c) for c in plaintext]
    cipher = "".join(
        [hex(square_and_multiply(it, e, n))[2:].zfill(256) for it in plaintext]
    )
    return str_to_base64("".join(cipher))


def rsa_decryption(ciphertext: str, n: int, d: int):
    """
    RSA decryption.
    Args:
        inp(str): A base64 encoded ciphertext.
        n(int): Modulus
        d(int): Private exponent.
    Returns:
        (str): plaintext.
    """
    ciphertext = base64_to_str(ciphertext)
    ciphertext = [ciphertext[i : i + 256] for i in range(0, len(ciphertext), 256)]
    plain = [square_and_multiply(int(it, 16), d, n) for it in ciphertext]
    return "".join(chr(it) for it in plain)


def rsa_decryption_crt(ciphertext: str, p: int, q: int, d):
    """
    Use CRT to speed up RSA decryption.
    Args:
        inp(str): A base64 encoded ciphertext.
        p(int): Very large prime.
        q(int): Very large prime.
        d(int): Private exponent.
    Returns:
        (str): plaintext.
    """

    def crt(x: int, p: int, q: int, d: int) -> str:
        xp = x % p
        xq = x % q
        dp = d % (p - 1)
        dq = d % (q - 1)
        yp = square_and_multiply(xp, dp, p)
        yq = square_and_multiply(xq, dq, q)
        cp = pow(q, -1, p)
        cq = pow(p, -1, q)
        return (q * cp * yp + p * cq * yq) % (p * q)

    ciphertext = base64_to_str(ciphertext)
    ciphertext = [ciphertext[i : i + 256] for i in range(0, len(ciphertext), 256)]
    plain = [crt(int(it, 16), p, q, d) for it in ciphertext]
    return "".join(chr(it) for it in plain)


def get_parser():
    parser = argparse.ArgumentParser(
        prog="RSA.py",
        description="RSA key generation, encryption and decryption.",
    )
    g = parser.add_mutually_exclusive_group()
    g.add_argument("-i", action="store_true", help="key Generation for RSA")
    g.add_argument(
        "-e",
        "--encrypt",
        metavar=("[plaintext]", "[n]", "[e]"),
        nargs=3,
        help="encrypt with given N and E",
    )
    g.add_argument(
        "-d",
        "--decrypt",
        metavar=("[ciphertext]", "[n]", "[d]"),
        nargs=3,
        help="decrypt with given N and D",
    )
    g.add_argument(
        "-CRT",
        metavar=("[ciphertext]", "[p]", "[q]", "[d]"),
        nargs=4,
        help="using CRT to speed up encryption",
    )
    return parser


def main():
    args = get_parser().parse_args()
    if args.i:
        rsa_key_gen()
        return
    elif args.encrypt:
        print(
            rsa_encryption(
                args.encrypt[0], int(args.encrypt[1], 10), int(args.encrypt[2], 10)
            ),
        )
        return
    elif args.decrypt:
        print(
            rsa_decryption(
                args.decrypt[0], int(args.decrypt[1], 10), int(args.decrypt[2], 10)
            )
        )
        return
    elif args.CRT:
        print(
            rsa_decryption_crt(
                args.CRT[0],
                int(args.CRT[1], 10),
                int(args.CRT[2], 10),
                int(args.CRT[3], 10),
            )
        )
        return

    # k = rsa_key_gen()
    # inp = "Test the program without args, uncomment it to use!!"
    # ciphertext_base64 = rsa_encryption(inp, k["n"], k["e"])
    # print(ciphertext_base64)
    # print(rsa_decryption(ciphertext_base64, k["n"], k["d"]))
    # print(rsa_decryption_crt(ciphertext_base64, k["p"], k["q"], k["d"]))


if __name__ == "__main__":
    main()
