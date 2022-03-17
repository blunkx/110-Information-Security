# Introduction to Information Security
# HW1
# Encryption B10830020

import sys
import argparse


def caesar(plain_text: str, key: int):
    try:
        key = int(key)
    except ValueError:
        print("key must be an integer")
        sys.exit()
    cipher_text = ""
    for c in plain_text:
        if c.isalpha():
            cipher_ascii = ord(c.upper()) + key
            cipher_ascii = (cipher_ascii - ord("A")) % 26 + ord("A")
            cipher_char = chr(cipher_ascii)
            cipher_text += cipher_char
        else:
            cipher_text += c

    return cipher_text


def playfair(plain_text: str, key: str):
    plain_text = str.upper(plain_text)
    key = str.upper(key)
    # add x if letter are same and along in the end
    plainList = []
    if len(plain_text) % 2 != 0:
        plain_text += "X"
    for index in range(0, len(plain_text) + 1, 2):
        if index < len(plain_text) - 1:
            if plain_text[index] == plain_text[index + 1]:
                plainList.append((plain_text[index], "X"))
            else:
                plainList.append((plain_text[index], plain_text[index + 1]))

    # build key list
    key_list = []
    for c in key:
        if c not in key_list:
            if c == "J":
                key_list.append("I")
            else:
                key_list.append(c)

    for index in range(ord("A"), ord("Z") + 1):
        if chr(index) not in key_list:
            if chr(index) == "J":
                if "I" not in key_list:
                    key_list.append("I")
            else:
                key_list.append(chr(index))

    # build key matrix
    key_matrix = [[0 for i in range(5)] for j in range(5)]
    for i in range(0, 5):
        for j in range(0, 5):
            key_matrix[i][j] = key_list.pop(0)

    def indexLocator(k):
        i = 0
        for row in key_matrix:
            j = 0
            for c in row:
                if c == k:
                    return (i, j)
                j += 1
            i += 1
        print("allocation error in indexLocator", k)

    cipherList = []

    for plainPair in plainList:

        p1 = plainPair[0] if plainPair[0] != "j" else "I"
        p2 = plainPair[1] if plainPair[1] != "j" else "I"

        p1Location = indexLocator(p1)
        p2Location = indexLocator(p2)

        # print(p1Location, p2Location)

        if p1Location[1] == p2Location[1]:
            i1 = (p1Location[0] + 1) % 5
            j1 = p1Location[1]

            i2 = (p2Location[0] + 1) % 5
            j2 = p2Location[1]

            cipherList.append((key_matrix[i1][j1], key_matrix[i2][j2]))

        elif p1Location[0] == p2Location[0]:
            i1 = p1Location[0]
            j1 = (p1Location[1] + 1) % 5

            i2 = p2Location[0]
            j2 = (p2Location[1] + 1) % 5
            cipherList.append((key_matrix[i1][j1], key_matrix[i2][j2]))

        else:
            i1 = p1Location[0]
            j1 = p1Location[1]

            i2 = p2Location[0]
            j2 = p2Location[1]

            cipherList.append((key_matrix[i1][j2], key_matrix[i2][j1]))

    cipher_text = ""
    for cipherPair in cipherList:
        cipher_text += cipherPair[0] + cipherPair[1]
    return cipher_text


def vernam(plain_text: str, key: str):

    key += plain_text[: len(plain_text) - len(key)]

    plain_bin = [ord(c.lower()) - ord("a") for c in plain_text]

    key_bin = [ord(c.lower()) - ord("a") for c in key]

    cipherBin = [(plain_bin[i] ^ key_bin[i]) for i in range(len(plain_bin))]

    # return cipherBin
    cipher_text = ""
    for i in cipherBin:
        cipher_text += chr(i % 26 + ord("A"))

    return cipher_text


def railfence(plain_text: str, key):
    try:
        key = int(key)
    except ValueError:
        print("key must be an integer")
        sys.exit()

    # build fence
    fence = [["#"] * len(plain_text) for _ in range(key)]
    rail = 0
    for x in range(len(plain_text)):
        fence[rail][x] = plain_text[x]
        if rail >= key - 1:
            dr = -1
        elif rail <= 0:
            dr = 1
        rail += dr

    cipher_text = ""

    # read fence
    for rail in range(key):
        for x in range(len(plain_text)):
            if fence[rail][x] != "#":
                cipher_text += fence[rail][x]

    return cipher_text.upper()


def row(plain_text: str, key: str):

    while len(plain_text) % len(key) != 0:
        plain_text += " "

    chunks = [plain_text[i : i + len(key)] for i in range(0, len(plain_text), len(key))]

    order = ["".join(sorted(key)).find(x) for x in key]

    plantext_map = map(lambda k: [c for (y, c) in sorted(zip(order, k))], chunks)

    matrix = []
    for l in plantext_map:
        matrix.append(l)

    cipher_text = ""
    for i in range(len(key)):
        for l in matrix:
            cipher_text += l[i]
    return cipher_text.upper()


def get_parser():
    parser = argparse.ArgumentParser(
        prog="encrypt.py",
        description="encrypt plaintext by the method and key entered by the user",
    )
    parser.add_argument("-m", "--method", help="the encryption method")
    parser.add_argument("-i", "--input", help="the plaintext to encrypt")
    parser.add_argument("-k", "--key", help="the encryption key")
    return parser


def main():
    args = get_parser().parse_args()
    dispatcher = {
        "caesar": caesar,
        "playfair": playfair,
        "vernam": vernam,
        "railfence": railfence,
        "row": row,
    }
    print(dispatcher[args.method](args.input, args.key))


if __name__ == "__main__":
    main()
