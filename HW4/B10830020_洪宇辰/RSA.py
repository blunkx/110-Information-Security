import math
import argparse
import random
import base64
import re


# genertate a random number for a given digit
def get_random(n: int):
    return random.randrange(2**(n - 1) + 1, 2**n - 1)


# prime list before 350, for low level prime number test
first_primes_list = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349
]


# filter is input number are relative prime with prime number in first_primes_list
def is_low_level_passed(input: int):
    for divisor in first_primes_list:
        if input % divisor == 0 and divisor**2 <= input:
            return False
    else:
        return True


# filter input by Miller Rabin test
def is_high_level_passed(input: int):
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


# generate two prime number which passed all test and not same with an given digit n
def generate_2_prime(n: int):

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


# RSA generate [p,q,phi,e,d] with 1024 digit and print them all
def rsa_generate_key():
    p, q = generate_2_prime(1024)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    while (True):
        if (math.gcd(e, phi) == 1):
            break
        e = random.randrange(1, phi)

    d = pow(e, -1, phi)

    key = {
        'p': p,
        'q': q,
        'N': n,
        'phi': phi,
        'e': e,
        'd': d,
    }

    def _str_():
        for k, v in key.items():
            print(f'{k} = {v}')

    _str_()
    return key


# RSA encryption by given plaintext and key generate from rsa_generate_key
def rsa_encrypt(plaintext: str, n: int, e: int):

    plain_bytes = str.encode(plaintext)
    cipher_bytes = [hex(pow(plain_byte, e, n)) for plain_byte in plain_bytes]
    cipher_bytes = "".join(cipher_bytes)
    cipher_base64 = base64.b64encode(
        cipher_bytes.encode("ascii")).decode("ascii")
    return cipher_base64


# RSA decrption by given ciphertext(in base64) and private key generate from rsa_generate_key
def rsa_decrypt(cipher_base64: str, n: int, d: int):
    ciphertext = base64.b64decode(
        cipher_base64.encode("ascii")).decode("ascii")

    cipher_bytes = ["0x" + part for part in ciphertext.split("0x") if part]

    plaintext = [chr(pow(int(byte, 16), d, n)) for byte in cipher_bytes]
    plaintext = "".join(plaintext)
    return plaintext


# RSA decrption in CRT mode by given ciphertext(in base64) and p,q,d generate from rsa_generate_key
def rsa_crt(cipher_base64: str, p: int, q: int, d: int):
    dp = pow(d, 1, (p - 1))
    dq = pow(d, 1, (q - 1))
    qinv = pow(p, 1, q)

    def crt(c):
        m1 = pow(c, dp, p)
        m2 = pow(c, dq, q)
        h = (qinv * (m1 - m2)) % p
        m = m2 + h * q
        return m

    ciphertext = base64.b64decode(
        cipher_base64.encode("ascii")).decode("ascii")
    cipher_bytes = ["0x" + part for part in ciphertext.split("0x") if part]
    plaintext = [chr(crt(int(byte, 16))) for byte in cipher_bytes]
    plaintext = "".join(plaintext)
    return plaintext


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
    parser.add_argument(
        "-e",
        "--encrypt",
        nargs=3,
        help="Encrypt mode need $RSA.py -e [msg] [N] [e]",
    )
    parser.add_argument(
        "-d",
        "--decrypt",
        nargs=3,
        help="Decrypt mode need $RSA.py -d [ciphertext] [N] [d]",
    )

    parser.add_argument(
        "-CRT",
        "--CRT",
        nargs=4,
        help="CRT mode need $RSA.py -crt [ciphertext] [p] [q] [d]",
    )
    return parser


def main():
    args = get_parser().parse_args()
    # if get -i parameter
    if (args.init):
        rsa_generate_key()
    # if get -e parameter
    if (args.encrypt):
        print(
            rsa_encrypt(
                args.encrypt[0],
                int(args.encrypt[1]),
                int(args.encrypt[2]),
            ))
    # if get -d parameter
    if (args.decrypt):
        print(
            rsa_decrypt(
                args.decrypt[0],
                int(args.decrypt[1]),
                int(args.decrypt[2]),
            ))
    # if get -CRT parameter
    if (args.CRT):
        print(
            rsa_crt(
                args.CRT[0],
                int(args.CRT[1]),
                int(args.CRT[2]),
                int(args.CRT[3]),
            ))


if __name__ == "__main__":
    main()

    ## test program

    key = rsa_generate_key()
    # ciphertext = rsa_encrypt('Hello RSA by b10830020', key['N'], key['e'])
    # print(ciphertext)
    # plaintext = rsa_decrypt(ciphertext, key['N'], key['d'])
    # print(plaintext)
    # plaintext = rsa_crt(ciphertext, key['p'], key['q'], key['d'])
    # print(ciphertext, key['p'], key['q'], key['d'])
    # print(plaintext)
