import hashlib
import json
import math
import os
import socket
import sys
import threading
import time

from factorise import *
from helper import *
from ipaddress import ip_address
from pathlib import Path
from random import getrandbits
from random import randrange
from random import sample
from struct import *


def get_ip():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432  # The port used by the server
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
msg = create_message(
    s_addr=s_addr, d_addr=d_addr, opcode=OP_CODES['PUBKEY'], y=Ya, p=p, q=q, alpha=alpha
)
s.sendall(msg)
print("Send: PUBKEY ==> ", display(unpack_message(msg), opcode=OP_CODES['PUBKEY']))

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
    action = action.strip()
    if action == "signup":
        user_id = input('Enter User ID: ')
        user_password = input('Enter User password: ')
        idx = encrypt(user_id, key)
        pwd = encrypt(user_password, key)
        msg = create_message(
            s_addr=s_addr,
            d_addr=d_addr,
            opcode=OP_CODES['LOGINCREAT'],
            ID=idx,
            password=pwd,
            dummy=encrypt(str(qa), key),
        )
        if msg == "Err":
            continue
        print(
            "Sent: LOGINCREAT ==> ",
            display(unpack_message(msg), OP_CODES['LOGINCREAT']),
        )
        s.sendall(msg)
        msg = s.recv(calcsize(FORMAT))
        msg = unpack_message(msg)
        print("Received: LOGINREPLY ==>", end=" ")
        if msg['status'] == 0:
            print("UNSUCCESSFULL")
            print('UserID already exists!!: ', user_id)
        else:
            print("SUCCESSFULL")
            print('SignUp Successfull!!. You can now login with ID: ', user_id)

    elif action == "login":
        if logged_user != "":
            print("User already logged in. Log out first before new login!!")
            continue
        user_id = input('Enter User ID: ')
        user_password = input('Enter User Password: ')
        idx = encrypt(user_id, key)
        pwd = encrypt(user_password, key)
        msg = create_message(
            s_addr=s_addr,
            d_addr=d_addr,
            opcode=OP_CODES['AUTHREQUEST'],
            ID=idx,
            password=pwd,
        )
        if msg == "Err":
            continue
        print(
            "Sent: AUTHREQUEST ==> ",
            display(unpack_message(msg), opcode=OP_CODES['AUTHREQUEST']),
        )
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
            print('Successfully Logged in as: ', user_id)
            logged_user = user_id

    elif action == "chat":
        if logged_user == "":
            print("Unable to chat. Login required!!")
            continue
        message = input('Enter the message to send: ')
        if len(message) > MAX_LEN:
            print("Message length exceeded!!. Choose small messsage (<= 1024 chars)")
            continue
        E, S = generate_signature(
            message, {'p': p, 'q': q, 'alpha': alpha}, {'private': Xa, 'public': Ya}
        )
        S = str(S)
        message = encrypt(message, key)
        idx = encrypt(logged_user, key)
        msg = create_message(
            s_addr=s_addr,
            d_addr=d_addr,
            opcode=OP_CODES['SIGNEDMSG'],
            ID=idx,
            e=E,
            s=S,
            plaintext=message,
        )

        print(
            "Sent: SIGNEDMSG ==> ",
            display(unpack_message(msg), opcode=OP_CODES['SIGNEDMSG']),
        )
        s.sendall(msg)
        # receiving verification status from the server
        msg = s.recv(calcsize(FORMAT))
        msg = unpack_message(msg)
        print("Received: VERSTATUS ==>", end=" ")
        if msg['status'] == 1:
            print("SUCCESSFULL")
            print("Successfully verified message!!")
        else:
            print("UNSUCCESSFULL (Message verfication failed!!)")

    elif action == "download":
        if logged_user == "":
            print("Unable to request file. Login required!!")
            continue
        filepath = input('Enter file path on server: ')
        filepath = encrypt(filepath, key)
        idx = encrypt(logged_user, key)
        msg = create_message(
            s_addr=s_addr,
            d_addr=d_addr,
            opcode=OP_CODES['SERVICEREQUEST'],
            ID=idx,
            file=filepath,
        )
        if msg == "Err":
            continue
        print(
            "Sent: SERVICEREQUEST ==> ",
            display(unpack_message(msg), opcode=OP_CODES['SERVICEREQUEST']),
        )
        s.sendall(msg)
        msg = s.recv(calcsize(FORMAT))
        msg = unpack_message(msg)
        print("Received: SERVICEDONE ==>", end=" ")
        if msg['status'] == -1:
            print("UNSUCCESSFULL (File does not exists on server!!)")
            continue
        else:
            file = decrypt(msg['file'], key)
            # file_content = decrypt(msg['buf'], key)
            file_content = msg['buf']
            f = open(file, 'wb')
            f.write(file_content)
            print(display(msg, opcode=OP_CODES['SERVICEDONE']))
            last_msg = ""
            while msg['status'] == 0:
                msg = s.recv(calcsize(FORMAT))
                msg = unpack_message(msg)
                print(display(msg, opcode=OP_CODES['SERVICEDONE']))
                if msg['status'] == 0:
                    # file_content = decrypt(msg['buf'], key)
                    file_content = msg['buf']
                    f.write(file_content)
            f.close()
            try:
                assert msg['status'] == 1
            except AssertionError:
                print("UNSUCCESSFULL (Requested file couldn't transmitted!!)")
                continue
            print("SUCCESSFULL")
            print("Sucessfully transmitted requested file!!")

    elif action == "quit" or action == "exit":
        msg = create_message(
            s_addr=s_addr, d_addr=d_addr, opcode=OP_CODES['EXITSTATUS']
        )
        s.sendall(msg)
        exit()

    elif action == "logout":
        logged_user = ""
        print('Closing session... Logout successfull!!')

    else:
        print("No such action!!")
        print("Choose one among the below actions:")
        print("""1. login\n2. signup\n3. chat\n4. download\n5. logout\n6. quit/exit""")
