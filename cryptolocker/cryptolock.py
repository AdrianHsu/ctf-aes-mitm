#!/usr/bin/env python3
import sys
import hashlib
from AESCipher import *

class SecureEncryption(object):
    def __init__(self, keys):
        assert len(keys) == 4
        self.keys = keys
        self.ciphers = []
        for i in range(4):
            self.ciphers.append(AESCipher(keys[i]))

    def enc(self, plaintext): # Because one encryption is not secure enough
        print(len(plaintext))
        one        = self.ciphers[0].encrypt(plaintext)
        print(len(one))
        two        = self.ciphers[1].encrypt(one)
        print(len(two))
        three      = self.ciphers[2].encrypt(two)
        print(len(three))
        ciphertext = self.ciphers[3].encrypt(three)
        print(len(ciphertext))
        return ciphertext

    def dec(self, ciphertext):
        three      = AESCipher._unpad(self.ciphers[3].decrypt(ciphertext))
        print(len(three))
        two        = AESCipher._unpad(self.ciphers[2].decrypt(three))
        print(len(two))
        one        = AESCipher._unpad(self.ciphers[1].decrypt(two))
        print(len(one))
        plaintext  = AESCipher._unpad(self.ciphers[0].decrypt(one))
        print(len(plaintext))
        return plaintext

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./cryptolock.py file-you-want-to-encrypt password-to-use")
        exit()

    # Read file to be encrypted
    filename = sys.argv[1]
    plaintext = open(filename, "rb").read()
    # print(plaintext)
    user_input = sys.argv[2].encode('utf-8')
    print(user_input.decode('utf-8'))

    assert len(user_input) == 8
    i = len(user_input) // 4
    print(i)
    keys = [ # Four times 256 is 1024 Bit strength!! Unbreakable!!
        hashlib.sha256(user_input[0:i]).digest(),
        hashlib.sha256(user_input[i:2*i]).digest(),
        hashlib.sha256(user_input[2*i:3*i]).digest(),
        hashlib.sha256(user_input[3*i:4*i]).digest(),
    ]
    # print(keys)
    s = SecureEncryption(keys)
    print('plaintext: ' , plaintext)
    ciphertext = s.enc(plaintext)
    plaintext_ = s.dec(ciphertext)
    assert plaintext == plaintext_
    # print('\n')
    print('ciphertext: ' , ciphertext)
    open(filename+".encrypted", "wb").write(ciphertext)
