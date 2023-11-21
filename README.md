# 110-Information-Security
### Installation
```bash
pip install -r requirements.txt
```
Install all required packages using the package manager [pip].

## HW1 Classical En/Decryption
### How to use?
```bash
python3 encrypt/decrypt.py –m [method] –i [input] –k [key]
```
-m : Encryption/decryption method.

-i : The text you want to encrypt/decrypt.

-k : The key used for ecryption/decryption.

|Method|Key|
|-|-|
|caesar| shift(int)|
|playfair| key(str)|
|vernam| key(str)|
|railfence| number of row(int)|
|row| order(int)|

### Report
[PDF](https://docs.google.com/document/d/1u9HDONgRzsCr-Fp47HMneMprQxHHhGH2PUbafW-xT5g/edit?usp=sharing)

## HW2 DES 
```bash
python3 encrypt/decrypt.py –i [input] –k [key]
```
-i : The text you want to encrypt/decrypt.

-k : The key used for ecryption/decryption.

Both input and key must be entered in hexadecimal format, e.g. `0x123`.

### Report
[PDF](https://docs.google.com/document/d/1xD6Ee5z5ZayHnT6eqFuwDBt8VF11NrFuBdH6HtHVQIY/edit?usp=sharing)

## HW4 RSA
```bash
python3 RSA.py [-i | -e [plaintext] [n] [e] | -d [ciphertext] [n] [d] | -CRT [ciphertext] [p] [q] [d]]
```
-i : key Generation for RSA

-e : encrypt with given N and E

-d : decrypt with given N and D

-CRT : using CRT to speed up encryption

