import pyDes
import json

key_file = open("SharedFiles/receiver.json")
key_file_string = json.load(key_file)

receiver_rsa_private_key = key_file_string['receiver']

def power(base, exp, mod):
    ans = 1
    base %= mod
    while exp != 0:
        if exp & 1:
            ans = (ans * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return ans

def decryptRSA(plain_text, key):
    return power(plain_text, int(key['d']), int(key['n']))

def decryptDES_ECB(data, key):
    k = pyDes.des(key, pyDes.ECB, IV=None, pad=None, padmode=pyDes.PAD_PKCS5)
    return k.decrypt(data, padmode=pyDes.PAD_PKCS5)


def retrieveMessage(data):
    session_key = data[0:16]
    session_key = int.from_bytes(session_key, byteorder = "big")
    session_key = decryptRSA(session_key, receiver_rsa_private_key)
    session_key = session_key.to_bytes(8 , byteorder = "big")

    mail = data[16:]
    return decryptDES_ECB(mail, session_key)

data = b'K\xa1\xb4\x9d\x0b(\x05\xdcE\xcc!d\x036X\x89\xa778/\xdd\t\x9eY\x8e[x\x02\x87\xaa\x9f\xed'

print(retrieveMessage(data))