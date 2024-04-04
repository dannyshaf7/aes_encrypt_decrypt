# Client program
# Connects to the server at port 7777
# Sends a message to the server, receives a reply and closes the connection
# Use Python 3 to run
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html
import math

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
from signal import signal, SIG_DFL, SIGFPE #\SIGPIPE
import sys
import time

signal(SIGFPE, SIG_DFL)
# create a socket object
connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# get local machine name
host = socket.gethostname()
# This port is where the server is listening
port = 7777
# connect to hostname on the port. Note that (host,port) is a tuple.
connection_socket.connect((host, port))


def check_inputs(keysize, mode):
    keysize_flag = True
    mode_flag = True
    mode = mode.lower()
    if keysize != "128" and keysize != "192" and keysize != "256":
        print("Invalid key size")
        keysize_flag = False
    if mode != "ecb" and mode != "cbc":
        print("Invalid mode")
        mode_flag = False
    if keysize_flag and mode_flag:
        keysize_bytes = int(int(keysize) / 8)
        aes_key = get_random_bytes(keysize_bytes)
        return True, aes_key, mode
    else:
        connection_socket.close()
        return False, None, None


continue_flag = True
aes_key = b''
iv = b''
mode = ""
if len(sys.argv) < 3:
    print("Too few arguments")
    continue_flag = False
    connection_socket.close()
elif len(sys.argv) > 3:
    print("Too many arguments")
    continue_flag = False
    connection_socket.close()
else:
    continue_flag, aes_key, mode = check_inputs(sys.argv[1], sys.argv[2])
    if continue_flag:
        print("key generated: ", aes_key)
        connection_socket.send(aes_key)
        time.sleep(1)
        mode_bytes = mode.encode()
        connection_socket.send(mode_bytes)
    else:
        connection_socket.close()


while continue_flag:
    # Takes input from user to send to server
    userInput = input("Please enter a message to send to the server: "
                      "(enter 'bye' to exit)")
    # check whether input is exit message
    if userInput != "bye":
        # Encode the message into bytes
        messageBytes = userInput.encode(encoding="utf-8")
        if mode == "ecb":
            if len(messageBytes) < 1020:
                cipher = AES.new(aes_key, AES.MODE_ECB)
                ct_bytes = cipher.encrypt(pad(messageBytes, AES.block_size))
                ct_string = ct_bytes.decode(encoding="utf-8", errors="ignore")
                print("key: ", aes_key, "\nencrypted text: ", ct_string, "\n")
                # Send the bytes through the connection socket
                connection_socket.send(ct_bytes)
            else:
                frags= math.ceil(len(messageBytes) / 1020)
                newByte = bytearray(b'')
                cipher = AES.new(aes_key, AES.MODE_ECB)
                # send number of fragments 
                ct_bytes = cipher.encrypt(pad(str(frags), AES.block_size))
                ct_string = ct_bytes.decode(encoding="utf-8", errors="ignore")
                connection_socket.send(ct_string)
                for i in messageBytes:
                    for x in range((frags-1), 0, -1):
                        newByte.append(i.to_bytes(1, sys.byteorder))
                        if len(newByte) == 1020 or i==(len(messageBytes)-1):
                            ct_bytes = cipher.encrypt(pad(newByte, AES.block_size))
                            ct_string = ct_bytes.decode(encoding="utf-8", errors="ignore")
                            print("key: ", aes_key, "\nencrypted text: ", ct_string, "\n")
                            # Send the bytes through the connection socket
                            connection_socket.send(ct_bytes)
                            newString=b''
        elif mode == "cbc":
            iv = get_random_bytes(AES.block_size)
            connection_socket.send(iv)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(messageBytes, AES.block_size))
            ct_string = ct_bytes.decode(encoding="utf-8", errors="ignore")
            print("key: ", aes_key, "\niv: ", iv, "\nencrypted text: ", ct_string, "\n")
            # Send the bytes through the connection socket
            connection_socket.send(ct_bytes)
        else:
            print("Error: encrypt modes")
            connection_socket.close()
        # Receive the message from the client (receive no more than 1024 bytes)
        msg_received = connection_socket.recv(1024)
        if mode == "ecb":
            cipher = AES.new(aes_key, AES.MODE_ECB)
            pt_bytes = unpad(cipher.decrypt(msg_received), AES.block_size)
            received_plaintext = pt_bytes.decode()
            print("decrypted message: ", received_plaintext)
        elif mode == "cbc":
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            pt_bytes = unpad(cipher.decrypt(msg_received), AES.block_size)
            received_plaintext = pt_bytes.decode()
            print("decrypted message: ", received_plaintext)
    else:
        connection_socket.close()
        print("\nThank you for using Team Kida's AES encryption program. Goodbye!\n")
        continue_flag = False