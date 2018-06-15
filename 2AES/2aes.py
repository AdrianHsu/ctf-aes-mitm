#!/usr/bin/env python3
# Python 3.6.4

from Crypto.Cipher import AES
import math
import time
import numpy as np

class DoubleAES():
    def __init__(self, key0, key1):
        self.aes128_0 = AES.new(key=key0, mode=AES.MODE_ECB)
        self.aes128_1 = AES.new(key=key1, mode=AES.MODE_ECB)

    def encrypt(self, s):
        return self.aes128_1.encrypt(self.aes128_0.encrypt(s))

    def decrypt(self, data):
        return self.aes128_0.decrypt(self.aes128_1.decrypt(data))

def int2bytes(n):
    return bytes.fromhex('{0:032x}'.format(n))


def crack():
    plaintext = 'NoOneUses2AES_QQ'
    plaintext_enc = plaintext.encode('utf-8')
    ciphertext = 'f1a0cff39c4351102e5cad9d63acc3ef'
    cipher = int2bytes(int(ciphertext, 16))
    # print(cipher)


    DESCipher1 = []
    DESCipher2 = []

    rounds = pow(2, 23)
    tBegin = time.time()
    for i in range(rounds):
        key = int2bytes(i)

        enc = AES.new(key, AES.MODE_ECB).encrypt(plaintext_enc)

        DESCipher1.append(enc)

        dec = AES.new(key, AES.MODE_ECB).decrypt(cipher)
        DESCipher2.append(dec)

        print('round', i , '/', rounds, 'done')
    tEnd = time.time()
    print('[1] total time: ', tEnd - tBegin, " sec")

    tBegin = time.time()
    intersect = np.intersect1d(np.array(DESCipher1), np.array(DESCipher2))

    tEnd = time.time()
    print('intersect: ', intersect)
    print('[2] total time: ', tEnd - tBegin, " sec")

    tBegin = time.time()
    if intersect.size != 1:
        print('key should only match once, error!')
        exit(0)
    else:
        index1 = np.where( DESCipher1 == intersect )
        firstKey = index1[0][0]
        index2 = np.where( DESCipher2 == intersect )
        secondKey = index2[0][0]
    tEnd = time.time()

    print('key1: ', str(firstKey))
    print('key2: ', str(secondKey))
    print('[3] total time: ', tEnd - tBegin, " sec")

    # firstKey = 6809501
    firstKey = firstKey * (pow(2, 23))
    # secondKey = 3927445

    open("key", "w").write(str(firstKey+secondKey))
    print('done: write keys')

def test():
    # flag = open('flag').read().strip()
    # assert len(flag) == 32

    key = int(open('key').read())
    assert key < 2**46
    key0, key1 = key // (2**23), key % (2**23)
    assert key0 < 2**23 and key1 < 2**23

    aes2 = DoubleAES(key0=int2bytes(key0), key1=int2bytes(key1))

    plaintext = 'NoOneUses2AES_QQ'
    ciphertext_ans = 'f1a0cff39c4351102e5cad9d63acc3ef'
    ciphertext = aes2.encrypt(plaintext).hex()
    print(plaintext, '->', ciphertext)

    assert ciphertext == ciphertext_ans

    target = '019847278c949131611d267c3bb1f833bdb8e692f12f237b90d900aeb17be714'
    
    target_b = bytes(bytearray.fromhex(target))
    flag = aes2.decrypt(target_b).decode('utf-8')
    open("flag.dec", "w").write(flag)

    flag_enc = aes2.encrypt(flag).hex()
    assert flag_enc == target
    print(flag, '->', flag_enc)


if __name__ == '__main__':
    crack()
    test()