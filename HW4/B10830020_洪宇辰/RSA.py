from pydoc import plain
import sys
import argparse
import random
import base64


def get_random(n):
    return random.randrange(2**(n - 1) + 1, 2**n - 1)


first_primes_list = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349
]


def is_low_level_passed(input):
    for divisor in first_primes_list:
        if input % divisor == 0 and divisor**2 <= input:
            return False
    else:
        return True


def is_high_level_passed(input):
    max_div = 0
    e = input - 1
    while e % 2 == 0:
        e >>= 1
        max_div += 1
    assert (2**max_div * e == input - 1)

    def trialComposite(round_tester):
        if pow(round_tester, e, input) == 1:
            return False
        for i in range(max_div):
            if pow(round_tester, 2**i * e, input) == input - 1:
                return False
        return True

    round = 20
    for i in range(round):
        round_tester = random.randrange(2, input)
        if trialComposite(round_tester):
            return False
    return True


def generate_2_prime(n):

    while (True):
        p = get_random(n)
        if (is_low_level_passed(p)):
            if (is_high_level_passed(p)):
                break
    while (True):
        q = get_random(n)
        if (q != p):
            if (is_low_level_passed(q)):
                if (is_high_level_passed(q)):
                    break
    return p, q


def gcd(a, b):
    if a > b:
        small = b
    else:
        small = a
    for i in range(1, small + 1):
        if ((a % i == 0) and (b % i == 0)):
            gcd = i

    return gcd


def modInverse(a, m):
    m0 = m
    y = 0
    x = 1

    if (m == 1):
        return 0

    while (a > 1):

        q = a // m

        t = m

        m = a % m
        a = t
        t = y

        y = x - q * y
        x = t

    if (x < 0):
        x = x + m0

    return x


def rsa_init():
    p, q = generate_2_prime(1024)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    while (True):
        if (is_low_level_passed(e)):
            if (is_high_level_passed(e)):
                break
        e = random.randrange(1, phi)

    d = modInverse(e, phi)

    print(f'p = {p}')
    print(f'q = {q}')
    print(f'N = {n}')
    print(f'phi = {phi}')
    print(f'e = {e}')
    print(f'd = {d}')


def rsa_encrypt(args):
    decoded = args[0].encode()
    msg = int.from_bytes(decoded, byteorder="big")
    e = int(args[1])
    n = int(args[2])
    cipher = pow(msg, e, n)
    cipher_byte = cipher.to_bytes((cipher.bit_length() + 7) // 8,
                                  byteorder="big")
    print(base64.b64encode(cipher_byte).decode())
    # print(cipher)
    return


def rsa_decrypt(args):
    decoded = base64.b64decode(args[0])
    msg = int.from_bytes(decoded, byteorder="big")
    d = int(args[1])
    n = int(args[2])
    plain = pow(msg, d, n)
    print(plain)
    return


def rsa_crt(msg, n, d):
    decrypted = pow(msg, d, n)
    return


def get_parser():
    parser = argparse.ArgumentParser(
        prog="RSA.py",
        description="RSA with: init, decrypt, encrypt, CRT mode.",
    )
    parser.add_argument(
        "-i",
        "--init",
        help="Init mode",
        action='store_true',
    )
    parser.add_argument("-e",
                        "--encrypt",
                        nargs=3,
                        help="Encrypt mode need $RSA.py -e [msg] [N] [e]")
    parser.add_argument(
        "-d",
        "--decrypt",
        nargs=3,
        help="Decrypt mode need $RSA.py -d [ciphertext] [N] [d]")

    parser.add_argument(
        "-CRT",
        "--crt",
        nargs=3,
        help="CRT mode need $RSA.py -crt [ciphertext] [N] [d]",
    )
    return parser


def main():
    args = get_parser().parse_args()
    if (args.init):
        rsa_init()
    if (args.encrypt):
        rsa_encrypt(args.encrypt)
    if (args.decrypt):
        rsa_decrypt(args.decrypt)
    if (args.crt):
        rsa_crt(args.crt)


if __name__ == "__main__":
    main()