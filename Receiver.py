import pyDes
import json
import smtplib
import time
import imaplib
import email
import re

key_file = open("SharedFiles/receiver.json")
key_file_string = json.load(key_file)

receiver_rsa_private_key = key_file_string['receiver']


def receiveMail():
    receiver_email = "mina.karam96@eng-st.cu.edu.eg"    
    password = input("Type your mail password and press enter: ")
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(receiver_email,password)
    mail.select('inbox')

    type, data = mail.search(None, 'ALL')
    mail_ids = data[0]

    id_list = mail_ids.split()   
    first_email_id = int(id_list[0])
    latest_email_id = int(id_list[-1])

    message = ""
    for i in range(latest_email_id,first_email_id, -1):
        typ, data =  mail.fetch(str(i), "(RFC822)")

        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_string(response_part[1].decode())
                message = msg.get_payload(decode=True)
                break
        break
    #print(message)
    groups = re.findall('[0-9]+' , str(message))

    return int(groups[1]).to_bytes(int(groups[0]) , byteorder = "big")


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
    return decryptDES_ECB(mail, session_key).decode("utf-8") 

receivedMessage = receiveMail()
print(retrieveMessage(receivedMessage))
