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


def prepare(key):
    pos = 1
    res = 0
    for i in range(48):
        if key & (1<<i):
            res |= (1<<pos)
        pos += 1
        if pos % 8 == 7:
            pos+=2
    return res


def BruteForce(plain_text , cipher):
    key = 0
    while(1):
        #print(key)
        k = prepare(key)
        if encryptDES_ECB(plain_text ,k.to_bytes(8 , byteorder = "big")) == cipher:
            return k
        key += 1


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

# magdy's
   #     0.02798295021057129
   #     4
   #     4
   #     1.012420654296875
   #     616
   #     616
   #     2.3386592864990234
   #     1658
   #     1658
   #     4.468438625335693
   #     3660
   #     3660
   #     6.0695202350616455
   #     3702
   #     3702
   #     10.828471899032593
   #     7710
   #     7710
   #     30.609933137893677
   #     22028
   #     22028
   #     82.71259450912476
   #     156798
   #     156798
   #     140.8682668209076
   #     396348
   #     396348
   #     239.89950823783875
   #     664610
   #     664610
