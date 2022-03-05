# Introduction to Information Security
# HW1
# Encryption B10830002


def caesar(plainText, key):
    cipherText = ""
    for c in plainText:
        if c.isalpha():
            cipherASCII = ord(c) + key
            if cipherASCII > ord('z'):
                cipherASCII -= 26
            cipherChar = chr(cipherASCII)
            cipherText += cipherChar
    return cipherText


def playfair(plainText, key):

    # add x if letter are same and along in the end
    plainList = []
    if len(plainText) % 2 != 0:
        plainText.append('X')
    for index in range(0, len(plainText)+1, 2):
        if index < len(plainText)-1:
            if plainText[index] == plainText[index+1]:
                plainList.append((plainText[index], 'X'))
            else:
                plainList.append((plainText[index], plainText[index+1]))

    # build key list
    keyList = []
    for c in key:
        if c not in keyList:
            if c == 'J':
                keyList.append('I')
            else:
                keyList.append(c)

    for index in range(ord('A'), ord('Z')):
        if chr(index) not in keyList:
            if chr(index) == 'J' and 'I' not in keyList:
                keyList.append("I")
            else:
                keyList.append(chr(index))

    # build key matrix
    keyMatrix = [[0 for i in range(5)] for j in range(5)]
    for i in range(0, 5):
        for j in range(0, 5):
            keyMatrix[i][j] = keyList.pop(0)

    def indexLocator(c):
        for i, keyrow in keyMatrix:
            for j, k in keyrow:
                if c == k:
                    return (i, j)

    cipherList = []

    for plainPair in plainList:
        p1 = plainPair[0] if plainPair[0] is not 'j' else 'I'
        p2 = plainPair[1] if plainPair[1] is not 'j' else 'I'

        p1Location = indexLocator(plainText[i], keyMatrix)
        p2Location = indexLocator(plainText[i+1], keyMatrix)

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

    cipherText = ''
    for cipherPair in cipherList:
        cipherText += cipherPair[0]+cipherPair[1]
    return cipherText


def vernam(plainText, key):

    plainBin = [ord(c) for c in plainText]
    keyBin = [ord(c) for c in key]

    for i in range(len(plainBin) - len(keyBin)):
        keyBin.append(keyBin[i])

    cipherBin = [plainBin[i] ^ keyBin[i]
                 for i in range(len(plainBin))]  # XOR vernam operation
    cipherText = ''
    for i in cipherBin:
        cipherText += chr(i)

    return cipherText
