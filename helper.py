import os
import sys
import socket
import threading
import hashlib
import math
import time
import json
from pathlib import Path
from struct import *
from ipaddress import ip_address
from random import randrange, getrandbits, sample
from helper import *
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
    "VERSTATUS": 90,
    "EXITSTATUS": 100
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


def get_params(LEN=LEN):
    pfs = set([])
    p = -1
    while(len(pfs) == 0):
        p = generate_prime_number(length=LEN)
        pfs = [num for num in factorise(p-1) if in_range(num, length=LEN//2)]
    q = sample(pfs, 1)[0]
    assert p != -1 and (p-1) % q == 0
    while True:
        g = randrange(2, p-2)
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
    # Average time taken to do pf of 128-bit number on my laptop is 3 minutes
    c = 0
    for i in range(k):
        a = time.time()
        p, q, alpha = get_params()
        b = time.time()
        c += b-a
    print("Average time: ", c/k)


# get_params_test()

def generate_signature(message, global_params, client_keys):
    print("\nGenerating Signature...\n")
    p = global_params['p']
    q = global_params['q']
    alpha = global_params['alpha']
    Xa, Ya = client_keys['private'], client_keys['public']
    k = randrange(1, q)
    e = pow_mod(alpha, k, p) % q
    hsh = hashlib.sha1(message.encode()).hexdigest()
    hsh_decimal = int(hsh, 16) % p
    s = pow_mod(k, q-2, q) * (hsh_decimal % q + (Xa*e) % q) % q
    s %= q
    return (e, s)


def verify_signature(signature, message, global_params, client_public_key):
    print("\nVerifying Signature...\n")
    e_dash, s_dash = int(signature['e']), int(signature['s'])
    p = global_params['p']
    q = global_params['q']
    alpha = global_params['alpha']
    Ya = client_public_key
    w = pow_mod(s_dash, q-2, q)
    u = hashlib.sha1(message.encode()).hexdigest()
    u_decimal = int(u, 16) % p
    u = (u_decimal*w) % q
    v = (e_dash*w) % q
    e_star = (pow_mod(alpha, u, p) * pow_mod(Ya, v, p)) % p
    e_star %= q
    return e_star == e_dash


def signature_test():
    message = "Hi! How are you ? I am using your service for past few months. I absolutely loved it and would definately recommend my colleagues. Appreciated all the hard work you putted in creating this wonderful service"
    print(message)
    blockPrint()
    p, q, alpha = get_params(LEN=47)
    enablePrint()
    Xa = randrange(1, q)  # client's private key
    Ya = pow_mod(alpha, Xa, p)  # client's public key
    a = time.time()
    print(p, q, alpha, Xa, Ya)
    e, s = generate_signature(message, {'p': p, 'q': q, 'alpha': alpha}, {
                              'private': Xa, 'public': Ya})
    b = time.time()
    print("Signature: ", e, s, "Time taken to generate signature: ", b-a)
    print(verify_signature({'e': e, 's': s}, message,
                           {'p': p, 'q': q, 'alpha': alpha}, Ya))

# signature_test()

# encrypt the input string using the given key using Caesar Cipher


def encrypt(string, key):
    '''
    Modified caesar cipher shift program that allows you to "encrypt"
    any given ASCII string (txt file) using a custom key.
    '''
    key_str = str(key)
    index = 0
    max_index = len(key_str)
    content = string
    out = ""
    for i in content:
        new_line = ""
        for letter in i:
            c_key = key_str[index % max_index]
            c_letter = ""
            if ord(c_key)+ord(letter) > 126:
                c_letter = chr(ord(c_key)+ord(letter)-126)
            else:
                c_letter = chr(ord(c_key) + ord(letter))
            new_line += c_letter
            index += 1
        out += new_line
    return str(out)

# Decrypt the input string using the given key using Caesar Cipher


def decrypt(string, key):
    key_str = str(key)
    content = string
    index = 0
    max_index = len(key_str)
    out = ""
    for i in content:
        new_line = ""
        for letter in i:
            c_key = key_str[index % max_index]
            c_letter = ""
            if ord(letter) - ord(c_key) < 0:
                c_letter = chr(ord(letter) - ord(c_key) + 126)
            else:
                c_letter = chr(ord(letter) - ord(c_key))
            new_line += c_letter
            index += 1
        out += new_line
    return str(out)

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
        temp = {'s_addr': out['s_addr'], 'd_addr': out['d_addr'], 'ID': out['ID'],
                'plaintext': out['plaintext'], 'e': out['e'], 's': out['s']}

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
