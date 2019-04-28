import pyDes
import random
import time
import pylab

import matplotlib.pyplot as plt

def generateSessionKey(len):
    session_key = 0
    rem = 8*6
    for i in range(8):
        session_key <<= 1
        for j in range(6):
            session_key <<= 1
            if rem > len:
                rem-=1
                continue
            c = random.randint(0, 1)
            session_key += c
        session_key <<= 1
    return  session_key


def encryptDES_ECB(data, key):
    data = data.encode()
    k = pyDes.des(key, pyDes.ECB, IV=None, pad=None, padmode=pyDes.PAD_PKCS5)
    d = k.encrypt(data)
    return d

def BruteForce(plain_text , cipher):
    key = 0
    while(1):
        #print(key)
        if encryptDES_ECB(plain_text , key.to_bytes(8 , byteorder = "big")) == cipher:
            return key
        key+=1

def BruteForce(plain_text , cipher):
    key = 0
    while(1):
        #print(key)
        if encryptDES_ECB(plain_text , key.to_bytes(8 , byteorder = "big")) == cipher:
            return key
        key += 1
        if key & (key - 1):
            lg = 0
            tmp = key
            while tmp != 0:
                lg += 1
                tmp >>= 1
            if lg % 8 == 1:
                key *= 2
            elif lg % 8 == 7:
                key *= 2


def Test():
    plain_text = "this is my message, please don't attack it"
    X = []
    Y = []
    pre = 0
    for i in range(6 , 19):
        key = generateSessionKey(i)
        while key <= pre:
            key = generateSessionKey(i)
        pre = key
        cipher = encryptDES_ECB(plain_text , key.to_bytes(8 , byteorder = "big"))
        t = time.time()
        k = BruteForce(plain_text , cipher)
        diff = time.time()-t
        print(diff)
        print(k)
        print(key)
        X.append(i)
        Y.append(diff)
    plt.xlabel('Key length (bits)')
    plt.ylabel('Time (seconds)')
    plt.title('DES bruteforce attack')
    plt.plot(X,Y)
    pylab.show()


Test()

   #     0.4737281799316406
   #     3.955752372741699
   #     9.826350688934326
   #     20.399290084838867
   #     35.76552224159241
   #     38.219075441360474
   #     77.8673906326294
   #     171.32871985435486
   #     6532.375683069229