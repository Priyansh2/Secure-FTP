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
from helper import *
# from sympy.ntheory import primefactors #slow for generating prime factors of 128 bit prime
from factorise import *


def get_ip():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
s_addr = get_ip()
d_addr = HOST
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
blockPrint()
p, q, alpha = get_params()
enablePrint()
Xa = randrange(1, q)  # client's private key
Ya = pow_mod(alpha, Xa, p)  # client's public key

# Sending public key tuple (Ya, p,q,alpha) to server
msg = create_message(s_addr=s_addr, d_addr=d_addr,
                     opcode=OP_CODES['PUBKEY'], y=Ya, p=p, q=q, alpha=alpha)
s.sendall(msg)
print("Send: PUBKEY ==> ", display(
    unpack_message(msg), opcode=OP_CODES['PUBKEY']))

# Receiving public key (Yb) from server
msg = s.recv(calcsize(FORMAT))
msg = unpack_message(msg)
Yb = msg['y']  # public to server
print("Received: PUBKEY ==> ", {'Yb': Yb})
# computing the shared key
key = pow_mod(Yb, Xa, p)
print("K_AB: ", key, "(Created session key!!)")  # Shared session key

logged_user = ""
qa = generate_prime_number(length=LEN)
while True:
    if logged_user == "":
        action = input('> ')
    else:
        action = input(logged_user + '> ')

    if action == "signup":
        user_id = input('Enter User ID: ')
        user_password = input('Enter User password: ')
        idx = encrypt(user_id, key)
        pwd = encrypt(user_password, key)
        msg = create_message(s_addr=s_addr, d_addr=d_addr,
                             opcode=OP_CODES['LOGINCREAT'], ID=idx, password=pwd, dummy=encrypt(str(qa), key))
        if(msg == "Err"):
            continue
        print("Sent: LOGINCREAT ==> ", display(
            unpack_message(msg), OP_CODES['LOGINCREAT']))
        s.sendall(msg)
        msg = s.recv(calcsize(FORMAT))
        msg = unpack_message(msg)
        print("Received: LOGINREPLY ==>", end=" ")
        if msg['status'] == 0:
            print("UNSUCCESSFULL")
            print('UserID already exists!!: ', decrypt(idx, key))
        else:
            print("SUCCESSFULL")
            print('SignUp Successfull!!. You can now login with ID: ',
                  decrypt(idx, key))

    elif action == "login":
        if logged_user != "":
            print("User already logged in. Log out first before new login!!")
            continue
        user_id = input('Enter User ID: ')
        user_password = input('Enter User Password: ')
        idx = encrypt(user_id, key)
        pwd = encrypt(user_password, key)
        msg = create_message(s_addr=s_addr, d_addr=d_addr,
                             opcode=OP_CODES['AUTHREQUEST'], ID=idx, password=pwd)
        if(msg == "Err"):
            continue
        print("Sent: AUTHREQUEST ==> ", display(
            unpack_message(msg), opcode=OP_CODES['AUTHREQUEST']))
        s.sendall(msg)
        msg = s.recv(calcsize(FORMAT))
        msg = unpack_message(msg)
        print("Received: AUTHREPLY ==>", end=" ")
        if msg['status'] == 0:
            print("UNSUCCESSFULL (User not found!!)")
        elif msg['status'] == -1:
            print("UNSUCCESSFULL (Password incorrect!!)")
        else:
            print("SUCCESSFULL")
            print('Successfully Logged in as: ', decrypt(idx, key))
            logged_user = decrypt(idx, key)

    elif action == "getfile":
        if logged_user == "":
            print("Unable to request file. Login required!!")
            continue
        filepath = input('Enter file path on server: ')
        idx = encrypt(logged_user, key)
        msg = create_message(s_addr=s_addr, d_addr=d_addr,
                             opcode=OP_CODES['SERVICEREQUEST'], ID=idx, file=filepath)
        if(msg == "Err"):
            continue
        print("Sent: SERVICEREQUEST ==> ", display(
            unpack_message(msg), opcode=OP_CODES['SERVICEREQUEST']))
        s.sendall(msg)
        msg = s.recv(calcsize(FORMAT))
        msg = unpack_message(msg)
        print("Received: SERVICEDONE ==>", end=" ")
        if(msg['status'] == -1):
            print("UNSUCCESSFULL (File does not exists on server!!)")
            continue
        else:
            f = open(msg['file'], 'w')
            f.write(msg['buf'])
            print(display(msg, opcode=OP_CODES['SERVICEDONE']))
            last_msg = ""
            while msg['status'] == 0:
                msg = s.recv(calcsize(FORMAT))
                msg = unpack_message(msg)
                f.write(msg['buf'])
                print(display(msg, opcode=OP_CODES['SERVICEDONE']))
                last_msg = msg
            f.close()
            msg = last_msg
            try:
                assert msg['status'] == 1
            except AssertionError:
                print("UNSUCCESSFULL (Requested file couldn't transmitted!!)")
                continue
            print("SUCCESSFULL")
            print("Requested file transmitted successfully!!")

    elif action == "quit" or action == "exit":
        exit()

    elif action == "logout":
        logged_user = ""
        print('Closing session... Logout Successfull!!')
    else:
        print("No such action!!")
        print("Choose one among the below actions:")
        print("""1. login\n2. signup\n3. getfile\n4. logout\n5. quit/exit""")