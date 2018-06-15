from AESCipher import *

from hashlib import sha256
from itertools import product
from string import printable

ciphertext = open('flag.encrypted', 'rb').read()
printable = printable[:-5]

password = ""
charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"  

for i in range(4):
    print("round {}".format(i + 1))
    possibilities = []
    for c1, c2 in product(charset, repeat=2):
        if c1 not in printable or c2 not in printable:
            continue
        me = (c1 + c2).encode('utf-8')
        key = sha256(me).digest()
        cipher = AESCipher(key)
        dec = cipher.decrypt(ciphertext)

        n = ord(chr(dec[-1]))
        if n < 32 and all(i == dec[-1] for i in dec[-n:]):
            print('padding length: {}'.format(n))
            possibilities.append((n, c1 + c2, dec))
    _, key, ciphertext = sorted(possibilities, reverse=True)[0]
    ciphertext = AESCipher._unpad(ciphertext)
    password = key + password
    print('found bytes: {}'.format(key))

with open('flag.dec', 'wb') as f:
    f.write(ciphertext)
print(password)