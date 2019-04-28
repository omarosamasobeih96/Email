import random
import pyDes
import math
receiver_rsa_public_key = {'e': 65537, 'n': 120622100426517990505120548700308202513}
def power(base, exp, mod):
    ans = 1
    base %= mod
    while exp != 0:
        if exp & 1:
            ans = (ans * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return ans

def encryptRSA(plain_text, key):
    return power(plain_text, key['e'], key['n'])

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

def generateMessage(mail , session_key):
    print(session_key)
    e = encryptRSA(session_key, receiver_rsa_public_key)
    print(e)
    encrypted_session_key = e.to_bytes(16 , byteorder = "big")
    encrypted_mail  = encryptDES_ECB(mail , session_key.to_bytes(8 , byteorder = "big"))
    return  encrypted_session_key + encrypted_mail

session_key = generateSessionKey(48)
mail = input()

print(generateMessage(mail, session_key))
