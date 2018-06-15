import signal, sys, os, time
import math
import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pwn import *

# parameter settings

NUM_OF_ROUNDS = 10
PWD_LENGTH    = NUM_OF_ROUNDS
IP            = 'linux13.csie.org'
PORT          = 7122

pwd_candidate = list(range(1, 21))

m = 0x12345678
p = 262603487816194488181258352326988232210376591996146252542919605878805005469693782312718749915099841408908446760404481236646436295067318626356598442952156854984209550714670817589388406059285064542905718710475775121565983586780136825600264380868770029680925618588391997934473191054590812256197806034618157751903

# function declaration

def printRound(server):
    round = server.recvuntil("\n", drop=True)
    # print(round)

def printFlag(server):
    flag = server.recvuntil("\n", drop=True).split(' ')[-1]
#    print(flag)
    return flag

def recvKeyFromServer(server):
    key = server.recvuntil("\n", drop=True).split(' ')[-1]
    return key

def sendKeyToServer(key, server):
    server.sendlineafter("Generate 'a' and send A = g^a mod p to the server: ", key)

def crackAndGetKey(s, pwd):
    B = recvKeyFromServer(s)
    g = pow(pwd, 2, p)
    gm = str(pow(g, m, p))
    sendKeyToServer(gm, s)
    return B

def getKey(s):
    B = recvKeyFromServer(s)
    return B

def sendKey(s, A):
    sendKeyToServer(A, s)

def crack():

    password = ""
    tBegin = time.time()
    for c in range(PWD_LENGTH):
        crack_index = c

        for i in pwd_candidate:
            print '[guess] (at crack index: ', crack_index, ') pwd: ', i, '/', pwd_candidate[-1]
            a = remote(IP, PORT)
            b = remote(IP, PORT)
            for j in range(NUM_OF_ROUNDS):
                print 'round ', j + 1

                printRound(a)
                printRound(b)
                if j == crack_index:
                    guess_pwd = int(hashlib.sha512(str(i)).hexdigest(), 16)
                    B = crackAndGetKey(a, guess_pwd)
                    A = crackAndGetKey(b, guess_pwd)
                    key1 = int(hashlib.sha512(str(pow(int(B), m, p))).hexdigest(), 16)
                    key2 = int(hashlib.sha512(str(pow(int(A), m, p))).hexdigest(), 16)
                else:
                    B = getKey(a)
                    A = getKey(b)
                    sendKey(a, A)
                    sendKey(b, B)

            flag_a = printFlag(a)
            flag_b = printFlag(b)

            # XOR
            result = int(flag_a) ^ int(flag_b) ^ key1 ^ key2
            if result == 0:
                print '[found] the pwd at index ', c, 'is: ', i
                password += str(i)
                if crack_index < (PWD_LENGTH - 1):
                    password += ','
                break

            a.close()
            b.close()
    tEnd = time.time()
    print '==========FINISHED=========='
    print 'total time: ', tEnd - tBegin, ' sec'
    print 'password: ', password
    open('password.dec', 'w').write(password)

def decode():
    password = open('password.dec', 'r').read().split(',')
    a = remote(IP, PORT)
    key = 0x00000000
    for i, word in enumerate(password):
        print 'word: ', i + 1, '/', PWD_LENGTH, ' (', word, ')'
        pwd = int(hashlib.sha512(word).hexdigest(), 16)
        #print pwd
        
        printRound(a)
        B = crackAndGetKey(a, pwd)
        K = pow(int(B), m, p)
        key ^= int(hashlib.sha512(str(K)).hexdigest(), 16)

    flag_a = printFlag(a)
    flag = int(flag_a) ^ key
    flag = str(hex(flag)[2:].decode("hex"))
    print flag
    open('flag.dec', 'w').write(flag)
        

if __name__ == '__main__':
    crack()
    decode()
