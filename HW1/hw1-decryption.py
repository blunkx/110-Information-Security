# Introduction to Information Security
# HW1
# Decryption B10830002
import click
import sys
from pathlib import Path


def read_file(file_name) -> str:
    file_path = Path(__file__).parent.resolve() / file_name
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
    try:
        shift = int(shift)
    except ValueError:
        print("Shift value must be an integer")
        sys.exit()
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
        return upper_table

    def decryption(table: dict, ciphertext: str) -> str:
        def get_key_by_val(d: dict, value):
            return list(d.keys())[list(d.values()).index(value)]

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
                        get_key_by_val(
                            table, ((table[alphabet][0] - 1) % 5, table[alphabet][1])
                        )
                    )
            elif table[pair[0]][0] == table[pair[1]][0]:
                for alphabet in pair:
                    plaintext.append(
                        get_key_by_val(
                            table, (table[alphabet][0], (table[alphabet][1] - 1) % 5)
                        )
                    )
            else:
                for i in range(2):
                    plaintext.append(
                        get_key_by_val(
                            table, (table[pair[i]][0], table[pair[(i + 1) % 2]][1])
                        )
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


def railfence():
    return "railfence"


def row():
    return "row"


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
    # python3 hw1-decryption.py -m caesar -i helloworld -k 4
    # python3 hw1-decryption.py -m vernam -i ABDBHBD -k a
    main()
