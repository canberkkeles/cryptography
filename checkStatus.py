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


stuID = 25393
stuID_B = 25388

E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator

# HERE CREATE A LONG TERM KEY
s_l, Q_l = 115142538846330665248457629218623207876906323769315896195871782827261793580115, Point(
    68979690099326004045929855866723528014580492514716676654579198582925599821708, 23540795897997141290375329348054416428337676069911719004640139437388947433477, E)


def checkStatus():
    h, s = signatureGeneration(str(stuID), P, n, s_l)

    # Check Status

    mes = {'ID_A': stuID, 'H': h, 'S': s}
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print("Status ", response.json())
