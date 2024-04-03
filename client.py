# Client program
# Connects to the server at port 7777
# Sends a message to the server, receives a reply and closes the connection
# Use Python 3 to run
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
from signal import signal, SIGPIPE, SIG_DFL
import sys
import time

signal(SIGPIPE, SIG_DFL)
# create a socket object
connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# get local machine name
host = socket.gethostname()
# This port is where the server is listening
port = 7777
# connect to hostname on the port. Note that (host,port) is a tuple.
connectionSocket.connect((host, port))


def check_inputs(keysize, mode):
    keysize_flag = True
    mode_flag = True
    mode = mode.lower()
    if keysize != "128" and keysize != "192" and keysize != "256":
        print("Invalid key size")
        keysize_flag = False
        # connectionSocket.close()
    if mode != "ecb" and mode != "cbc":
        print("Invalid mode")
        mode_flag = False
        # connectionSocket.close()
    if keysize_flag and mode_flag:
        keysize_bytes = int(int(keysize) / 8)
        aes_key = get_random_bytes(keysize_bytes)
        return True, aes_key, mode
    else:
        connectionSocket.close()
        return False, None, None


continue_flag = True
aes_key = b''
mode = ""
if len(sys.argv) < 3:
    print("Too few arguments")
    continue_flag = False
    connectionSocket.close()
elif len(sys.argv) > 3:
    print("Too many arguments")
    continue_flag = False
    connectionSocket.close()
else:
    continue_flag, aes_key, mode = check_inputs(sys.argv[1], sys.argv[2])
    if continue_flag:
        print("key generated: ", aes_key)
        connectionSocket.send(aes_key)
        time.sleep(1)
        mode_bytes = mode.encode()
        connectionSocket.send(mode_bytes)
    else:
        connectionSocket.close()


while continue_flag:
    # Takes input from user to send to server
    userInput = input("Please enter a message to send to the server: "
                      "(enter 'bye' to exit)")
    # check whether input is exit message
    if userInput != "bye":
        # Encode the message into bytes
        messageBytes = userInput.encode(encoding="utf-8")
        if mode == "ecb":
            cipher = AES.new(aes_key, AES.MODE_ECB)
            ct_bytes = cipher.encrypt(pad(messageBytes, AES.block_size))
            ct_string = ct_bytes.decode(encoding="utf-8", errors="ignore")
            print("key: ", aes_key, "\nencrypted text: ", ct_string, "\n")
            # Send the bytes through the connection socket
            connectionSocket.send(ct_bytes)
        elif mode == "cbc":
            iv = get_random_bytes(AES.block_size)
            connectionSocket.send(iv)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(messageBytes, AES.block_size))
            ct_string = ct_bytes.decode(encoding="utf-8", errors="ignore")
            print("key: ", aes_key, "\niv: ", iv, "\nencrypted text: ", ct_string, "\n")
            # Send the bytes through the connection socket
            connectionSocket.send(ct_bytes)
        else:
            print("Error: encrypt modes")
    else:
        connectionSocket.close()
        print("\nThank you for using Team Kida's AES encryption program. Goodbye!\n")
        continue_flag = False
