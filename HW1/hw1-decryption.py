# Introduction to Information Security
# HW1
# Decryption B10830002
import click
import sys
import math


def caesar(shift: int, plaintext: str) -> str:
    try:
        shift = int(shift)
    except ValueError:
        print("Shift value must be an integer")
        sys.exit()
    shift *= -1
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


def playfair(key: str, ciphertext: str) -> str:
    def create_table(key: str) -> dict:
        temp = key.upper()
        temp = temp.replace(" ", "")
        temp = temp.replace("J", "I")
        try:
            if not str.isalpha(temp):
                raise
        except Exception:
            print("Key Error")
            sys.exit()
        upper = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        upper_table = dict.fromkeys(list(upper), "")
        table = ""
        temp = list(temp)
        while temp:
            current_char = temp.pop(0)
            table += current_char
            temp = list(filter(lambda x: x != current_char, temp))
            upper = upper.replace(current_char, "")
        table += upper
        for i in table:
            upper_table[i] = (table.index(i) // 5, table.index(i) % 5)
            upper_table[(table.index(i) // 5, table.index(i) % 5)] = i
        return upper_table

    def decryption(table: dict, ciphertext: str) -> str:
        try:
            if len(ciphertext) % 2 != 0:
                raise
        except Exception:
            print("Ciphertext error")
            sys.exit()
        ciphertext = ciphertext.upper()
        ciphertext = ciphertext.replace(" ", "")
        ciphertext = ciphertext.replace("J", "I")
        pair_list = [tuple(ciphertext[i : i + 2]) for i in range(0, len(ciphertext), 2)]
        plaintext = []
        for pair in pair_list:
            if table[pair[0]][1] == table[pair[1]][1]:
                for alphabet in pair:
                    plaintext.append(
                        table[((table[alphabet][0] - 1) % 5, table[alphabet][1])]
                    )
            elif table[pair[0]][0] == table[pair[1]][0]:
                for alphabet in pair:
                    plaintext.append(
                        table[(table[alphabet][0], (table[alphabet][1] - 1) % 5)]
                    )
            else:
                for i in range(2):
                    plaintext.append(
                        table[(table[pair[i]][0], table[pair[(i + 1) % 2]][1])]
                    )
        plaintext = "".join(plaintext)
        return plaintext

    upper_table = create_table(key)
    return decryption(upper_table, ciphertext)


def vernam(key: str, ciphertext: str) -> str:
    key = key.upper()
    ciphertext = ciphertext.upper()
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plaintext = []
    for i, j in zip(ciphertext, range(len(ciphertext))):
        plaintext.append(upper[(upper.index(i) ^ upper.index(key[j])) % 26])
        key += plaintext[-1]
    plaintext = "".join(plaintext)
    return plaintext


def railfence(key: int, ciphertext: str) -> str:
    try:
        key = int(key)
    except ValueError:
        print("Key error")
        sys.exit()
    group_size = key * 2 - 2
    row_coor = []
    for i in range(len(ciphertext)):
        j = i % group_size
        if j >= key:
            j = key - (j % key + 1) - 1
        row_coor.append((j, i))
    row_coor.sort(key=lambda tup: tup[1])
    row_coor.sort(key=lambda tup: tup[0])
    order = [i[1] for i in row_coor]
    text = list(ciphertext)
    plaintext = dict(zip(order, text))
    plaintext = "".join(dict(sorted(plaintext.items())).values())
    return plaintext


def row(key: str, ciphertext: str) -> str:
    key_len = len(key)
    row_num = math.ceil(len(ciphertext) / key_len)
    cols = [
        list(ciphertext[i : i + row_num]) for i in range(0, len(ciphertext), row_num)
    ]
    col_order = dict(zip(list(range(1, key_len + 1)), cols))
    rows = [[] for i in range(row_num)]
    for i in key:
        try:
            i = int(i)
        except ValueError:
            print("Key error")
            sys.exit()
        for row, col in zip(rows, col_order[i]):
            row.append(col)
    plaintext = ""
    for row in rows:
        plaintext += "".join(row)
    return plaintext


@click.command()
@click.option("-m", "--method", "method", required=True, help="The decryption method")
@click.option(
    "-i",
    "--input",
    "inp",
    default="ciphertext",
    required=True,
    help="The ciphertext to decrypt",
)
@click.option("-k", "--key", "key", required=True, help="The decryption key")
def main(method, inp, key):
    dispatcher = {
        "caesar": caesar,
        "playfair": playfair,
        "vernam": vernam,
        "railfence": railfence,
        "row": row,
    }
    print(dispatcher[method](key, inp))


if __name__ == "__main__":
    # python3 hw1-decryption.py -m playfair -i RSCLKUVUQKFW -k youlooksnice
    # python3 hw1-decryption.py -m caesar -i lippsasvph -k 4
    # python3 hw1-decryption.py -m vernam -i ABDBHBD -k a
    # python3 hw1-decryption.py -m railfence -i GsGsekfrekeoe -k 3
    # python3 hw1-decryption.py -m railfence -i MEMATRHTGPRYETEFETEOAAT -k 2
    # python3 hw1-decryption.py -m railfence -i WECRUOERDSOEERNTNEAIVDAC -k 3
    main()
