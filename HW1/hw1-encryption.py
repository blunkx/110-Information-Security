# Introduction to Information Security
# HW1
# Encryption B10830020


def caesar(plainText, key):
    cipherText = ""
    for c in plainText:
        if c.isalpha():
            cipherASCII = ord(c) + key
            if cipherASCII > ord("z"):
                cipherASCII -= 26
            cipherChar = chr(cipherASCII)
            cipherText += cipherChar
        else:
            cipherText += c

    return cipherText


def playfair(plainText:str, key):
    plainText=str.upper(plainText)
    # add x if letter are same and along in the end
    plainList = []
    if len(plainText) % 2 != 0:
        plainText += "X"
    for index in range(0, len(plainText) + 1, 2):
        if index < len(plainText) - 1:
            if plainText[index] == plainText[index + 1]:
                plainList.append((plainText[index], "X"))
            else:
                plainList.append((plainText[index], plainText[index + 1]))

    # build key list
    keyList = []
    for c in key:
        if c not in keyList:
            if c == "J":
                keyList.append("I")
            else:
                keyList.append(c)

    for index in range(ord("A"), ord("Z") + 1):
        if chr(index) not in keyList:
            if chr(index) == "J":
                if "I" not in keyList:
                    keyList.append("I")
            else:
                keyList.append(chr(index))

    # build key matrix
    keyMatrix = [[0 for i in range(5)] for j in range(5)]
    for i in range(0, 5):
        for j in range(0, 5):
            keyMatrix[i][j] = keyList.pop(0)

    def indexLocator(k):
        i = 0
        for row in keyMatrix:
            j = 0
            for c in row:
                if c == k:
                    return (i, j)
                j += 1
            i += 1

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

            cipherList.append((keyMatrix[i1][j1], keyMatrix[i2][j2]))

        elif p1Location[0] == p2Location[0]:
            i1 = p1Location[0]
            j1 = (p1Location[1] + 1) % 5

            i2 = p2Location[0]
            j2 = (p2Location[1] + 1) % 5
            cipherList.append((keyMatrix[i1][j1], keyMatrix[i2][j2]))

        else:
            i1 = p1Location[0]
            j1 = p1Location[1]

            i2 = p2Location[0]
            j2 = p2Location[1]

            cipherList.append((keyMatrix[i1][j2], keyMatrix[i2][j1]))

    cipherText = ""
    for cipherPair in cipherList:
        cipherText += cipherPair[0] + cipherPair[1]
    return cipherText


def vernam(plainText, key):

    # plainBin = []
    # for c in plainText:
    #         plainBin.append(ord(c))

    # for i in range(len(plainBin) - len(keyBin)):
    #     keyBin.append(keyBin[i])

    while len(plainText) > len(key):
        key += plainText
        break

    plainBin = [ord(c) for c in plainText]

    keyBin = [ord(c) for c in key]

    cipherBin = [
        (plainBin[i] ^ keyBin[i]) for i in range(len(plainBin))
    ]  # XOR vernam operation

    # return cipherBin

    cipherText = ""
    for i in cipherBin:
        cipherText += chr(i)

    return cipherText


def railfence(plainText, key):

    # build fence
    fence = [["#"] * len(plainText) for _ in range(key)]
    rail = 0
    for x in range(len(plainText)):
        fence[rail][x] = plainText[x]
        if rail >= key - 1:
            dr = -1
        elif rail <= 0:
            dr = 1
        rail += dr

    cipherText = ""

    # read fence
    for rail in range(key):
        for x in range(len(plainText)):
            if fence[rail][x] != "#":
                cipherText += fence[rail][x]

    return cipherText


def row_transposition(plainText, key):

    while len(plainText) % len(key) != 0:
        plainText += " "

    chunks = [plainText[i : i + len(key)] for i in range(0, len(plainText), len(key))]

    order = ["".join(sorted(key)).find(x) for x in key]

    plantextMap = map(lambda k: [c for (y, c) in sorted(zip(order, k))], chunks)

    matrix = []
    for l in plantextMap:
        matrix.append(l)

    cipherText = ""
    for i in range(len(key)):
        for l in matrix:
            cipherText += l[i]
    return cipherText


print(caesar("hello word", 3))

print(playfair("HELLOWORD", "HEY"))

print(vernam(vernam("hello word", "hey"), "hey"))

print(railfence("hello word", 3))

print(row_transposition("hello word", "hey"))
