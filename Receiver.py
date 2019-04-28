import pyDes

receiver_rsa_private_key = {'d': 66947041837651485204243804806200296449, 'n': 120622100426517990505120548700308202513}

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
    return power(plain_text, key['d'], key['n'])

def decryptDES_ECB(data, key):
    k = pyDes.des(key, pyDes.ECB, IV=None, pad=None, padmode=pyDes.PAD_PKCS5)
    return k.decrypt(data, padmode=pyDes.PAD_PKCS5)


def retrieveMessage(data):
    session_key = data[0:16]
    session_key = int.from_bytes(session_key, byteorder = "big")
    print(session_key)
    session_key = decryptRSA(session_key, receiver_rsa_private_key)
    print(session_key)
    session_key = session_key.to_bytes(8 , byteorder = "big")

    mail = data[16:]
    return decryptDES_ECB(mail, session_key)

data = b'\x02bs&\x07\x91\xf3\x01\xd7\xf7\xfe\x8a\xb5m\xc3\x95\xe1X\xe7\x14\xfbn\x96\xa1[,\xd2\xc4\xca\xa1I\x19\xa5K\xb9\xb4\xb9\xd3j\xeb'

print(retrieveMessage(data))