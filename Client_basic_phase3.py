import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import Crypto.Random.random
import random
import re
import json
import time
from sendEphemeralKeys import sendEphemeralKeys
from resetEphemeral import resetEphemeral
from checkStatus import checkStatus
from Crypto.Hash import HMAC, SHA256

API_URL = 'http://cryptlygos.pythonanywhere.com'


def keyGeneration(n, P):
    s_a = Crypto.Random.random.randint(1, n-1)
    Q_a = s_a * P
    return s_a, Q_a


def signatureGeneration(m, P, n, s_l):
    m_ = m.encode()
    k = Crypto.Random.random.randint(0, n-1)
    R = k * P
    r = (R.x) % n
    toHash = m_ + r.to_bytes((r.bit_length()+7)//8, byteorder='big')
    h_ = int.from_bytes(SHA3_256.new(toHash).digest(), "big")
    h = h_ % n
    s = (s_l * h + k) % n
    return h, s


def signatureVerification(m, P, Q_a, h, s):
    m_ = m.encode()
    V = s*P - h*Q_a
    v = V.x % n
    toHashPrime = m_ + v.to_bytes((v.bit_length()+7)//8, byteorder='big')
    hPrime_ = int.from_bytes(SHA3_256.new(toHashPrime).digest(), "big")
    hPrime = hPrime_ % n
    return hPrime == h


def sendMessage():
    h, s = signatureGeneration(str(stuID_B), P, n, s_l)
    mes = {'ID_A': stuID, 'ID_B': stuID_B, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqKey"), json=mes)
    if response.ok:
        res = response.json()
        myEphemeralIndex = int(res["i"])
        otherPartyEphemeralIndex = int(res["j"])
        QBj = Point(res["QBJ.x"], res["QBJ.y"], E)

        sAi = ephemeralKeys[myEphemeralIndex][0]
        QAi = ephemeralKeys[myEphemeralIndex][1]

        T = sAi * QBj
        U = str(T.x) + str(T.y) + "NoNeedToRunAndHide"
        KeyEncodeAB = SHA3_256.new(U.encode()).digest()
        KeyMacAB = SHA3_256.new(KeyEncodeAB).digest()

        message = str(input("Enter a message to send to the client: "))
        cipher = AES.new(KeyEncodeAB, AES.MODE_CTR)
        nonce = cipher.nonce
        ctext = cipher.encrypt(message.encode())
        hMac = HMAC.new(KeyMacAB, digestmod=SHA256)
        macCode = hMac.update(ctext).digest()

        msg = nonce + ctext + macCode
        msg = int.from_bytes(msg, "big")

        mes = {'ID_A': stuID, 'ID_B': stuID_B, 'I': myEphemeralIndex,
               'J': otherPartyEphemeralIndex, 'MSG': msg}
        response = requests.put('{}/{}'.format(API_URL, "SendMsg"), json=mes)
        print(response.json())

    else:
        sys.exit(response.json())


stuID = 25393
stuID_B = 20680

E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator


def printCommands():
    print("*************************************")
    print("WELCOME " + str(stuID) + "!")
    print("Enter S for sending a message to " + str(stuID_B))
    print("Enter Q for questioning your message status ")
    print("Enter R for receiving message ")
    print("Enter E for sending new keys to server ")
    print("Enter X for quiting... ")
    print("*************************************")


# HERE CREATE A LONG TERM KEY
s_l, Q_l = 115142538846330665248457629218623207876906323769315896195871782827261793580115, Point(
    68979690099326004045929855866723528014580492514716676654579198582925599821708, 23540795897997141290375329348054416428337676069911719004640139437388947433477, E)

# reset keys first
resetEphemeral()

# Generate Ephemeral Keys
ephemeralKeys = sendEphemeralKeys()


def receiveMessage():
    h, s = signatureGeneration(str(stuID), P, n, s_l)
    # Get your message
    mes = {'ID_A': stuID, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg_PH3"), json=mes)
    if(response.ok):
        response = response.json()
        idSender = response["IDB"]
        idEphemeral = response["KEYID"]
        msg = response["MSG"]
        QBj = Point(response["QBJ.X"], response["QBJ.Y"], E)

        print("Message from student " + str(idSender))

        # decrypt messages
        sAi = ephemeralKeys[int(idEphemeral)][0]
        QAi = ephemeralKeys[int(idEphemeral)][1]

        T = sAi * QBj
        U = str(T.x) + str(T.y) + "NoNeedToRunAndHide"
        KeyEncodeAB = SHA3_256.new(U.encode()).digest()
        KeyMacAB = SHA3_256.new(KeyEncodeAB).digest()

        ctext = msg.to_bytes((msg.bit_length()+7)//8, byteorder='big')

        mac = ctext[-32:]
        message = ctext[8:-32]

        cipher = AES.new(KeyEncodeAB, AES.MODE_CTR, nonce=ctext[0:8])
        dtext = (cipher.decrypt(message)).decode('UTF-8')
        print(dtext)

        hMac = HMAC.new(KeyMacAB, digestmod=SHA256)
        hMac.update(message)
        try:
            hMac.verify(mac)
            print("Message is authentic!")
        except ValueError:
            print("Message is not authentic")
    else:
        sys.exit(response.json())


while True:
    printCommands()
    command = str(input("Enter a command: "))
    command = command.upper()

    if command == "S":
        sendMessage()
    elif command == "Q":
        checkStatus()
    elif command == "R":
        receiveMessage()
    elif command == "E":
        resetEphemeral()
        ephemeralKeys = sendEphemeralKeys()
    elif command == "X":
        break
    else:
        print("Invalid command! ")
