import random
import pyDes
import math
import json
import smtplib, ssl

key_file = open("SharedFiles/public.json")
key_file_string = json.load(key_file)

receiver_rsa_public_key = key_file_string['receiver']
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
    return power(plain_text, int(key['e']), int(key['n']))

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
    e = encryptRSA(session_key, receiver_rsa_public_key)
    encrypted_session_key = e.to_bytes(16 , byteorder = "big")
    encrypted_mail  = encryptDES_ECB(mail , session_key.to_bytes(8 , byteorder = "big"))
    return  encrypted_session_key + encrypted_mail

def sendMail(body):
    port = 465  # For SSL
    smtp_server = "smtp.gmail.com"
    sender_email = "minamego001@gmail.com"  # Enter your address
    receiver_email = "mina.karam96@eng-st.cu.edu.eg"  # Enter receiver address
    password = input("Type your mail password and press enter: ")
    message = """\
    Subject: Hi there


    """ + body
    #print(message)
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)
        print("Mail Sent ^^")


session_key = generateSessionKey(48)
mail = input("Please enter your message: ")


encryptedMessage = generateMessage(mail, session_key)
l = len(encryptedMessage) 
intConv = int.from_bytes(encryptedMessage, byteorder='big', signed=False)
mailBody = str(l) + '+' + str(intConv)
#print(encryptedMessage)
sendMail(mailBody)
