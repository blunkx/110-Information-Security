#!/usr/bin/env python3
"""
Introduction to Information Security
HW2 DES
Encryption by B10830002
"""
import argparse


def des_encryption(key: str, plaintext: str) -> str:
    def initial_permutation(text: str) -> str:
        ip = [58, 50, 42, 34, 26, 18, 10, 2]
        ip += [60, 52, 44, 36, 28, 20, 12, 4]
        ip += [62, 54, 46, 38, 30, 22, 14, 6]
        ip += [64, 56, 48, 40, 32, 24, 16, 8]
        ip += [57, 49, 41, 33, 25, 17, 9, 1]
        ip += [59, 51, 43, 35, 27, 19, 11, 3]
        ip += [61, 53, 45, 37, 29, 21, 13, 5]
        ip += [63, 55, 47, 39, 31, 23, 15, 7]
        ip = [x - 1 for x in ip]
        ip_dict = dict(zip(list(range(64)), ip))
        text = list(text)
        temp = ["x" for _ in range(64)]
        for i in range(len(text)):
            temp[i] = text[ip_dict[i]]
        text = "".join(temp)
        return text

    def gen_subkeys(key: str) -> dict:
        def pc_1(key: str) -> str:
            """
            64bits key -> 56bits key
            """
            pc1 = [57, 49, 41, 33, 25, 17, 9, 1]
            pc1 += [58, 50, 42, 34, 26, 18, 10, 2]
            pc1 += [59, 51, 43, 35, 27, 19, 11, 3]
            pc1 += [60, 52, 44, 36, 63, 55, 47, 39]
            pc1 += [31, 23, 15, 7, 62, 54, 46, 38]
            pc1 += [30, 22, 14, 6, 61, 53, 45, 37]
            pc1 += [29, 21, 13, 5, 28, 20, 12, 4]
            pc1 = [x - 1 for x in pc1]
            pc1_dict = dict(zip(list(range(56)), pc1))
            key = list(key)
            temp = ["x" for _ in range(56)]
            for i in range(len(pc1)):
                temp[i] = key[pc1_dict[i]]
            key = "".join(temp)
            return key

        def pc2(key: str) -> str:
            """
            56bits key -> 48bits key
            """
            pc2 = [14, 17, 11, 24, 1, 5]
            pc2 += [3, 28, 15, 6, 21, 10]
            pc2 += [23, 19, 12, 4, 26, 8]
            pc2 += [16, 7, 27, 20, 13, 2]
            pc2 += [41, 52, 31, 37, 47, 55]
            pc2 += [30, 40, 51, 45, 33, 48]
            pc2 += [44, 49, 39, 56, 34, 53]
            pc2 += [46, 42, 50, 36, 29, 32]
            pc2 = [x - 1 for x in pc2]
            pc2_dict = dict(zip(list(range(48)), pc2))
            key = list(key)
            temp = ["x" for _ in range(48)]
            for i in range(len(pc2)):
                temp[i] = key[pc2_dict[i]]
            key = "".join(temp)
            return key

        def key_transform(round: int, c: str, d: str) -> tuple[str, str, str]:
            shift_one_rounds = [1, 2, 9, 16]
            if round in shift_one_rounds:
                temp, temp2 = c[1:], d[1:]
                temp += c[:1]
                temp2 += d[:1]
                c, d = temp, temp2
            else:
                temp, temp2 = c[2:], d[2:]
                temp += c[:2]
                temp2 += d[:2]
                c, d = temp, temp2
            key = pc2(c + d)
            return key, c, d

        key = pc_1(key)
        c, d = key[: len(key) // 2], key[len(key) // 2 :]
        subkeys = {}
        for i in range(1, 17):
            subkeys[i], c, d = key_transform(i, c, d)
        return subkeys

    def encryption_round(l: str, r: str, key: str) -> tuple[str, str]:
        def f_funtion(r: str, key: str) -> str:
            def expansion(r: str) -> str:
                e = [32, 1, 2, 3, 4, 5]
                e += [4, 5, 6, 7, 8, 9]
                e += [8, 9, 10, 11, 12, 13]
                e += [12, 13, 14, 15, 16, 17]
                e += [16, 17, 18, 19, 20, 21]
                e += [20, 21, 22, 23, 24, 25]
                e += [24, 25, 26, 27, 28, 29]
                e += [28, 29, 30, 31, 32, 1]
                e = [x - 1 for x in e]
                e_dict = dict(zip(list(range(48)), e))
                r = list(r)
                temp = ["x" for _ in range(48)]
                for i in range(len(e)):
                    temp[i] = r[e_dict[i]]
                r = "".join(temp)
                return r

            def s_box(inp: str) -> str:
                """
                48bits->32bits
                """
                six_bits_list = [inp[i : i + 6] for i in range(0, len(inp), 6)]
                boxes = {}
                boxes[1] = [
                    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
                ]
                boxes[2] = [
                    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
                ]
                boxes[3] = [
                    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
                ]
                boxes[4] = [
                    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
                ]
                boxes[5] = [
                    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
                ]
                boxes[6] = [
                    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
                ]
                boxes[7] = [
                    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
                ]
                boxes[8] = [
                    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
                ]
                four_bits_list = []
                for i in range(len(six_bits_list)):
                    row = int(six_bits_list[i][0] + six_bits_list[i][-1], 2)
                    column = int(six_bits_list[i][1:-1], 2)
                    four_bits_list.append(bin(boxes[i + 1][row][column])[2:].zfill(4))
                return "".join(four_bits_list)

            def permutation(inp: str) -> str:
                p = [16, 7, 20, 21, 29, 12, 28, 17]
                p += [1, 15, 23, 26, 5, 18, 31, 10]
                p += [2, 8, 24, 14, 32, 27, 3, 9]
                p += [19, 13, 30, 6, 22, 11, 4, 25]
                p = [x - 1 for x in p]
                p_dict = dict(zip((list(range(32))), p))
                inp = list(inp)
                result = ["x" for _ in range(len(inp))]
                for i in range(len(inp)):
                    result[i] = inp[p_dict[i]]
                return "".join(result)

            """
            do f funtion
            """
            r = expansion(r)
            temp = int(r, 2) ^ int(key, 2)
            temp = bin(temp)[2:].zfill(len(r))
            temp = s_box(temp)
            temp = permutation(temp)
            return temp

        after_f = f_funtion(r, key)
        l_ = int(after_f, 2) ^ int(l, 2)
        l = bin(l_)[2:].zfill(len(l))
        return r, l

    def final_permutation(inp: str) -> str:
        row_1 = [40, 8, 48, 16, 56, 24, 64, 32]
        ip_1 = []
        for i in range(8):
            ip_1 += [x - i for x in row_1]
        ip_1 = [x - 1 for x in ip_1]
        ip_1_dict = dict(zip(list(range(64)), ip_1))
        inp = list(inp)
        temp = ["x" for _ in range(64)]
        for i in range(len(inp)):
            temp[i] = inp[ip_1_dict[i]]
        return "".join(temp)

    key = bin(int(key, 16))[2:].zfill(64)
    plaintext = bin(int(plaintext, 16))[2:].zfill(64)
    plaintext = initial_permutation(plaintext)
    subkeys = gen_subkeys(key)
    l, r = plaintext[: len(plaintext) // 2], plaintext[len(plaintext) // 2 :]
    for i in range(1, 17):
        l, r = encryption_round(l, r, subkeys[i])
    ciphertext = final_permutation(r + l)
    ciphertext = hex(int(ciphertext, 2))[2:].zfill(16).upper()
    return "0x" + ciphertext


def get_parser():
    parser = argparse.ArgumentParser(
        prog="encrypt.py",
        description="encrypt ciphertext by DES",
    )
    parser.add_argument("-i", "--input", help="the plaintext to encrypt")
    parser.add_argument("-k", "--key", help="the encryption key")
    return parser


def main():
    args = get_parser().parse_args()
    print(des_encryption(args.key, args.input))


if __name__ == "__main__":
    main()
