import os
import sys
import socket
import threading
import hashlib
from pathlib import Path
from struct import *
from ipaddress import ip_address
from random import randrange, getrandbits, sample
import math
import time
import json
# from sympy.ntheory import primefactors #slow for generating prime factors of 128 bit prime
from factorise import *

# Disable 'print' calls


def blockPrint():
    sys.stdout = open(os.devnull, 'w')

# Restore 'print' calls


def enablePrint():
    sys.stdout = sys.__stdout__


# OPCodes
OP_CODES = {
    "LOGINCREAT": 10,
    "LOGINREPLY": 20,
    "AUTHREQUEST": 30,
    "AUTHREPLY": 40,
    "SERVICEREQUEST": 50,
    "SERVICEDONE": 60,
    "PUBKEY": 70,
    "SIGNEDMSG": 80,
    "VERSTATUS": 90
}

MAX_SIZE = 80
S_MAX_SIZE = 160
MAX_LEN = 1024
LEN = 85  # generate LEN-bit prime
FORMAT = 'hqq80s80s80s80s1024s80s160s80s80s80s1024sh80s'
bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def pow_mod(a, b, m):
    res = 1
    a = a % m
    while b:
        if b & 1:
            res = res*a % m
        a = a*a % m
        b = b >> 1
    return res


def check_composite(n, a, d, r):
    x = pow_mod(a, d, n)
    if x == 1 or x == n-1:
        return False
    for i in range(1, r):
        x = x * x % n
        if x == n-1:
            return False
    return True


def is_prime(n):
    if n < 2:
        return False
    r, d = 0, n-1
    while (d & 1) == 0:
        d = d >> 1
        r += 1
    for a in bases:
        if n == a:
            return True
        if check_composite(n, a, d, r):
            return False
    return True

# helper function to get random odd number bits as prime candidates


def generate_prime_candidate(length):
    # generate random bits
    p = getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p

# helper function to generate nbit prime number


def generate_prime_number(length=1024):
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

# test function to check average runtime of random nbit prime generator


def generator_test(k=100):
    # Average time is 4.5 seconds on my laptop for k=100
    c = 0
    for i in range(k):
        a = time.time()
        prime = generate_prime_number()
        b = time.time()
        c += b-a
    print("Average time: ", c/k)


# generator_test()

def in_range(num, length):
    if num > (1 << length-1) and num < (1 << length):
        return True
    return False

# function to find prime factors of a number


def find_prime_factors(num, length=160):
    pf = set([])
    while(num % 2 == 0):
        num //= 2
    for i in range(3, int(math.sqrt(num))+1):
        while num % i == 0:
            if in_range(i, length):
                pf.add(i)
            num //= i

    if num > 2 and in_range(num, length):
        pf.add(num)
    return pf


# get global parameters (p,q,alpha)


def get_params():
    pfs = set([])
    p = -1
    while(len(pfs) == 0):
        p = generate_prime_number(length=LEN)
        # pfs = find_prime_factors(p-1, length=LEN//2)
        # pfs = [num for num in primefactors(p-1) if in_range(num, length=LEN//2)] #import the dependency before using it
        pfs = [num for num in factorise(p-1) if in_range(num, length=LEN//2)]
    # print(len(pfs))
    q = sample(pfs, 1)[0]
    assert p != -1 and (p-1) % q == 0
    while True:
        g = randrange(2, p-1)
        alpha = pow_mod(g, (p-1)//q, p)
        if alpha > 1:
            break
    return (p, q, alpha)


'''a = time.time()
p, q, alpha = get_params()
b = time.time()
print(p, q, alpha, b-a)
print(type(p), type(q), type(alpha))
'''


def get_params_test(k=100):
    c = 0
    for i in range(k):
        a = time.time()
        p, q, alpha = get_params()
        b = time.time()
        c += b-a
    print("Average time: ", c/k)


# get_params_test()

# function to get the Casesar Cipher Encoding dictionary


def get_encoding():
    dict = {}
    r_dict = {}  # reverse mapping

    dict[' '] = 00
    r_dict[0] = ' '
    for i in range(65, 65 + 26):
        dict[chr(i)] = i-64
        r_dict[i-64] = chr(i)

    dict[','] = 27
    dict['.'] = 28
    dict['?'] = 29
    r_dict[27] = ','
    r_dict[28] = '.'
    r_dict[29] = '?'

    for i in range(48, 48 + 10):
        dict[chr(i)] = i-18
        r_dict[i-18] = chr(i)

    for i in range(97, 97 + 26):
        dict[chr(i)] = i-57
        r_dict[i-57] = chr(i)

    dict['!'] = 66
    r_dict[66] = '!'
    # print(dict)
    # print(r_dict)
    return (dict, r_dict)

# encrypt the input string using the given key using Caesar Cipher


def encrypt(string, key):
    dict, r_dict = get_encoding()
    keys = list(dict.keys())
    # print(keys)
    out = ""
    for char in string:
        if char not in keys:
            # print("Err: Invalid character")
            return -1
        else:
            now = dict[char]
            fin = ((now + key) % 67)
            # print(fin)
            out += r_dict[fin]
    return out

# Decrypt the input string using the given key using Caesar Cipher


def decrypt(string, key):
    dict, r_dict = get_encoding()
    keys = list(dict.keys())
    # print(keys)
    out = ""
    for char in string:
        if char not in keys:
            # print("Err: Invalid character")
            return -1
        else:
            now = dict[char]
            fin = ((now - key) % 67)
            out += r_dict[fin % 67]
    return out


# string = "Hello .World!"
# key = 112
# enc = encrypt(string, key)
# print("encrypted: ", enc)
# print(decrypt(enc, key))

def display(out, opcode=70):
    '''"LOGINCREAT": 10,
    "LOGINREPLY": 20,
    "AUTHREQUEST": 30,
    "AUTHREPLY": 40,
    "SERVICEREQUEST": 50,
    "SERVICEDONE": 60,
    "PUBKEY": 70,
    "SIGNEDMSG": 80,
    "VERSTATUS": 90'''
    temp = {}
    if opcode == 10:
        temp = {'s_addr': out['s_addr'], 'd_addr': out['d_addr'],
                'ID': out['ID'], 'password': out['password'], 'dummy': out['dummy']}
    if opcode == 20:
        pass
    if opcode == 30:
        temp = {'s_addr': out['s_addr'], 'd_addr': out['d_addr'],
                'ID': out['ID'], 'password': out['password']}
    if opcode == 40:
        pass
    if opcode == 50:
        temp = {'s_addr': out['s_addr'], 'd_addr': out['d_addr'],
                'ID': out['ID'], 'file': out['file']}
    if opcode == 60:
        temp = {'s_addr': out['s_addr'], 'd_addr': out['d_addr'], 'buf': out["buf"],
                'plaintext': out['plaintext'], 'file': out['file'], 'status': 'SUCCESSFULL'}
        if out['status'] == -1:
            temp["status"] = "UNSUCCESSFULL"
    if opcode == 70:
        temp = {'p': out['p'], 'q': out['q'],
                'alpha': out['alpha'], 'Y': out['y']}
    if opcode == 80:
        pass
    if opcode == 90:
        pass
    if opcode == 100:
        pass
    return temp

# function to unpack the packet of fixed size with different parameters


def unpack_message(packet):
    # Message components (16 components):
    # short opcode ==> opcode for a message
    # long long s_addr ==> source ipv4 address in integer form
    # long long d_addr ==>destination ipv4 address in integer form
    # long long p ==> very long prime p (global param)
    # long long q ==> long prime q | p-1 (global param)
    # long long alpha ==> global param
    # long long y ==> public key generated by user
    # char plaintext[MAX_LEN] ==> plaintext message
    # long long e ==> signature component
    # char s[S_MAX_SIZE] ==> signature component
    # char ID[MAX_SIZE] ==> encrypted user id
    # char password[MAX_SIZE] ==> encrypted user password
    # char file[MAX_SIZE] ==> File path on server
    # char buf[MAX_LEN] ==> part of transmitted file
    # short status ==> message status
    # long long  dummy ==> dummy variable in case you need
    opcode, s_addr, d_addr, p, q, alpha, y,  plaintext, e, s, ID,  password, file, buf, status, dummy = unpack(
        FORMAT, packet)
    out = {}
    out['opcode'] = opcode
    out['s_addr'] = str(ip_address(s_addr))
    out['d_addr'] = str(ip_address(d_addr))
    out['p'] = int(p.decode("ascii").rstrip('\x00'))
    out['q'] = int(q.decode("ascii").rstrip('\x00'))
    out['alpha'] = int(alpha.decode("ascii").rstrip('\x00'))
    out['y'] = int(y.decode("ascii").rstrip('\x00'))
    out['plaintext'] = plaintext.decode("ascii").rstrip('\x00')
    out['e'] = int(e.decode("ascii").rstrip('\x00'))
    out['s'] = s.decode("ascii").rstrip('\x00')
    out['ID'] = ID.decode("ascii").rstrip('\x00')
    out['password'] = password.decode("ascii").rstrip('\x00')
    out['file'] = file.decode("ascii").rstrip('\x00')
    out['buf'] = buf.decode("ascii").rstrip('\x00')
    out['status'] = status
    out['dummy'] = dummy.decode("ascii").rstrip('\x00')
    return out

# Create a Packet with input arguments


def create_message(opcode=10, s_addr="127.0.0.1", d_addr="127.0.0.1", p=134493393549233, q=21173393191, alpha=45595505996081, y=-1, plaintext="Hi!", e=-1, s="", ID="", password="", file="", buf="", status=0, dummy=""):
    # Message components:
    # short opcode ==> opcode for a message
    # long long s_addr ==> source ipv4 address in integer form
    # long long d_addr ==>destination ipv4 address in integer form
    # long long p ==> very long prime p (global param)
    # long long q ==> long prime q | p-1 (global param)
    # long long alpha ==> global param
    # long long y ==> public key generated by user
    # char plaintext[MAX_LEN] ==> plaintext message
    # long long e ==> signature component
    # char s[S_MAX_SIZE] ==> signature component
    # char ID[MAX_SIZE] ==> encrypted user id
    # char password[MAX_SIZE] ==> encrypted user password
    # char file[MAX_SIZE] ==> File path on server
    # char buf[MAX_LEN] ==> part of transmitted file
    # short status ==> message status
    # long long  dummy ==> dummy variable in case you need
    s_addr = int(ip_address(s_addr))
    d_addr = int(ip_address(d_addr))
    if len(plaintext) > MAX_LEN:
        print("Message length exceeded!!. Choose small messsage (<= 1024 chars)")
        return "Err"
    if len(s) > S_MAX_SIZE:
        print("Choose small s (<=160 chars)")
        return "Err"
    if len(ID) > MAX_SIZE:
        print("UserID is too large!!. Choose small UserID (<= 80 chars)")
        return "Err"
    if len(password) > MAX_SIZE:
        print("User Password is too large!!. Choose small password (<= 80 chars)")
        return "Err"
    if len(file) > MAX_SIZE:
        print("File length exceeded!!. Choose small file path!! (<= 80 chars)")
        return "Err"
    p = str(p)
    q = str(q)
    alpha = str(alpha)
    y = str(y)
    e = str(e)
    packet = pack(FORMAT, opcode, s_addr, d_addr, p.encode("ascii"), q.encode("ascii"), alpha.encode("ascii"), y.encode("ascii"), plaintext.encode("ascii"), e.encode("ascii"), s.encode(
        "ascii"), ID.encode("ascii"),  password.encode("ascii"), file.encode("ascii"), buf.encode("ascii"), status, dummy.encode("ascii"))
    return packet


'''
msg = create_message(opcode=7, s_addr="127.0.0.1", d_addr="127.0.0.1", p=134493393549233, q=21173393191, alpha=463427763, y=6438274211, plaintext="gasfs  dagdasg da dasda", e=675432,
                     s="dasdasdsad", ID="test_user01", password="hfghwhfgshdfghdsgfhdsghkfgdsh", file="random_file_path.txt", buf="vdagsdgas gadsdu ququuquuuqu", status=0, dummy=45595505996081)
print(msg, "\n")
print(calcsize(FORMAT), "\n")
print(unpack_message(msg))
'''
