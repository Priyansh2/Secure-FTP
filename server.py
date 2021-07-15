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


# password file dictionary on server
PASSWORD_FILE = {}


def display_table():
    print("<===============PASSWORD TABLE==================>")
    print(json.dumps(PASSWORD_FILE, sort_keys=True, indent=4))
    print("<===============================================>")


def get_ip():
    hostname = socket.gethostname()
    return socket.gethostbyname(hostname)


# function to check if userID and Password present in the PASSWORD_FILE


def check_creds(id, password):
    global PASSWORD_FILE
    password += str(PASSWORD_FILE[id]['salt']) + str(PASSWORD_FILE[id]['prime'])
    password = hashlib.sha1(password.encode()).hexdigest()
    if PASSWORD_FILE[id]['password'] == password:
        return 1
    return -1

# thread fuction for each client connnected


def threaded(conn, addr):
    s_addr = get_ip()
    d_addr = addr[0]

    # receiving public key tuple (Ya, p,q, alpha) from client

    #msg = conn.recv(calcsize(FORMAT))
    #msg = unpack_message(msg)
    try:
        msg = conn.recv(calcsize(FORMAT))
        msg = unpack_message(msg)
    except:
        print("Closing Connection with ==> ", d_addr)
        conn.close()
    print("Received: PUBKEY ==> ", display(
        msg, opcode=OP_CODES['PUBKEY']), " from ==> ", d_addr)
    Ya, p, q, alpha = msg['y'], msg['p'], msg['q'], msg['alpha']

    # computing Yb from global (p,q,alpha) received from client
    Xb = randrange(1, q)  # server's private Key
    Yb = pow_mod(alpha, Xb, p)  # server's public key

    # Sending public key (Yb) to client
    msg = create_message(s_addr=s_addr, d_addr=d_addr,
                         opcode=OP_CODES['PUBKEY'], y=Yb)
    print("Sent: PUBKEY ==> ", {"Yb": Yb}, " to ==> ", d_addr)
    conn.sendall(msg)
    # computing the shared session key with client
    key = pow_mod(Ya, Xb, p)
    print("K_BA created!==> ", key, " with ==> ", d_addr)

    while True:
        try:
            msg = conn.recv(calcsize(FORMAT))
            msg = unpack_message(msg)
        except:
            print("Closing Connection with ==> ", d_addr)
            break
        print("Received:", end=" ")
        if msg['opcode'] == OP_CODES['EXITSTATUS']:
            print("EXITSTATUS from ==> ", d_addr)
            break
        elif msg['opcode'] == OP_CODES['SIGNEDMSG']:
            print("SIGNEDMSG ==>", end=" ")
            ID = decrypt(msg['ID'], key)
            chat_msg = decrypt(msg['plaintext'], key)
            print({"ID": ID, "Message": chat_msg}, " FROM ==> ", d_addr)
            E = msg['e']
            S = msg['s']
            signature = {'e': E, 's': S}
            global_params = {'p': p, 'q': q, "alpha": alpha}
            client_public_key = Ya
            ver_status = verify_signature(
                signature, chat_msg, global_params, client_public_key)
            msg = create_message(s_addr=s_addr, d_addr=d_addr,
                                 opcode=OP_CODES['VERSTATUS'], status=int(ver_status))
            if ver_status:
                print("Message verified!!. Sent VERSTATUS ==> ", d_addr)
            else:
                print("Message verfication failed!!. Sent VERSTATUS ==> ", d_addr)
            conn.sendall(msg)

        elif msg['opcode'] == OP_CODES["LOGINCREAT"]:
            print("LOGINCREAT ==>", end=" ")
            ID = decrypt(msg['ID'], key)
            password = decrypt(msg['password'], key)
            dummy = decrypt(msg['dummy'], key)
            print({"ID": ID, "password": password,
                   "qa": dummy}, " FROM ==> ", d_addr)
            salt = getrandbits(13)  # getting a random salt
            password += str(salt) + str(dummy)
            # using sha-1 hash function
            password = hashlib.sha1(password.encode()).hexdigest()
            # add to password table
            if ID in PASSWORD_FILE.keys():
                msg = create_message(
                    s_addr=s_addr, d_addr=d_addr, opcode=OP_CODES['LOGINREPLY'], status=0)
                print("UserID already exists!!. Sent LOGINREPLY ==> ", d_addr)
                conn.sendall(msg)
            else:
                PASSWORD_FILE[ID] = {'password': password,
                                     'prime': int(dummy), 'salt': salt}
                display_table()
                msg = create_message(
                    s_addr=s_addr, d_addr=d_addr, opcode=OP_CODES['LOGINREPLY'], status=1)
                print("UserID created!!. Sent LOGINREPLY ==> ", d_addr)
                conn.sendall(msg)

        elif msg['opcode'] == OP_CODES['AUTHREQUEST']:
            print("AUTHREQUEST ==>", end=" ")
            ID = decrypt(msg['ID'], key)
            password = decrypt(msg['password'], key)
            print({"ID": ID, "password": password}, " FROM ==> ", d_addr)
            # check in table
            if ID not in PASSWORD_FILE.keys():
                msg = create_message(
                    s_addr=s_addr, d_addr=d_addr, opcode=OP_CODES['AUTHREPLY'], status=0)
                print("UserID does not exists!!. Sent AUTHREPLY ==> ", d_addr)
                conn.sendall(msg)
            else:
                status = check_creds(ID, password)
                msg = create_message(
                    s_addr=s_addr, d_addr=d_addr, opcode=OP_CODES['AUTHREPLY'], status=status)
                if(status == 1):
                    print("Request granted!!. Sent AUTHREPLY ==> ", d_addr)
                else:
                    print("Incorrect Password!!. Sent AUTHREPLY ==> ", d_addr)
                conn.sendall(msg)

        elif msg['opcode'] == OP_CODES['SERVICEREQUEST']:
            print("SERVICEREQUEST ==>", end=" ")
            ID = decrypt(msg['ID'], key)
            file = msg['file']
            filename = Path(file).name
            print({"ID": ID, "filename": filename}, " FROM ==> ", d_addr)
            if not os.path.isfile(file):
                msg = create_message(
                    s_addr=s_addr, d_addr=d_addr, opcode=OP_CODES['SERVICEDONE'],  status=-1)
                print("File does not exists on server!!. Sent SERVICEDONE ==> ", d_addr)
                conn.sendall(msg)
            else:
                filesize = os.path.getsize(file)
                f = open(file)
                print("Requested file found!!. Transferring... ==> ", d_addr)
                lim = 1024  # 1024 bytes of file at a time to client
                cnt = 1
                while True:
                    if filesize < 1024:
                        lim = -1
                    c = f.read(lim)
                    if not c:
                        #print("DEBUG: REACHED!!!!!", cnt)
                        break
                    msg = create_message(
                        s_addr=s_addr, d_addr=d_addr, opcode=OP_CODES['SERVICEDONE'], file=filename, buf=c, status=0, plaintext="Fragment"+str(cnt))
                    conn.sendall(msg)
                    cnt += 1
                msg = create_message(
                    s_addr=s_addr, d_addr=d_addr, opcode=OP_CODES['SERVICEDONE'], file=filename, status=1, plaintext="Thank you for using our service and have a nice day!")
                conn.sendall(msg)
                print("File transfer completed!!")
    conn.close()


HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
print("Server Listening...")
s.listen()
while True:
    conn, addr = s.accept()
    print('Connected! ==> ', addr)
    t = threading.Thread(target=threaded, args=(conn, addr,))
    t.start()
s.close()
