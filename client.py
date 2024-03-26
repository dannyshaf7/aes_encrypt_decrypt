# Client program
# Connects to the server at port 7777
# Sends a message to the server, receives a reply and closes the connection
# Use Python 3 to run
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html

# from Crypto.Cipher import AES
# from Crypto.Hash import HMAC, SHA256
# from Crypto.Random import get_random_bytes
import Encrypt_Decrypt
import socket
from signal import signal, SIGPIPE, SIG_DFL

signal(SIGPIPE, SIG_DFL)
# create a socket object
connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# get local machine name
host = socket.gethostname()
# This port is where the server is listening
port = 7777
# connect to hostname on the port. Note that (host,port) is a tuple.
connectionSocket.connect((host, port))
# This message will be sent to the server
# message = "Hello! I'm Daniel."

keysize = 192
mode = "ECB"
aes_key = ""
iv = ""
ct_bytes = ""

continueFlag = True
while continueFlag:
    # Takes input from user to send to server
    userInput = input("Please enter a message to send to the server: "
                      "(enter 'bye' to exit)")
    # check whether input is exit message
    if userInput != "bye":
        # Encode the message into bytes
        messageBytes = userInput.encode()
        if mode == "ECB":
            aes_key, ct_bytes = Encrypt_Decrypt.ecb_encrypt(keysize, userInput)
            ct_string = bytes.decode(ct_bytes)
            print("key: ", aes_key, "\nencrypted text: ", ct_string, "\n")
            # Send the bytes through the connection socket
            connectionSocket.send(aes_key, ct_bytes)
        elif mode == "CBC":
            aes_key, iv, ct_bytes = Encrypt_Decrypt.cbc_encrypt(keysize, messageBytes)
            ct_string = bytes.decode(ct_bytes)
            print("key: ", aes_key, "\niv: ", iv, "\nencrypted text: ", ct_string, "\n")
            # Send the bytes through the connection socket
            connectionSocket.send(ct_bytes)
        else:
            print("Error: encrypt modes")

        # Receive the message from the server (receive no more than 1024 bytes)
        receivedBytes = connectionSocket.recv(1024)
        if mode == "ECB":
            pt_bytes = Encrypt_Decrypt.ecb_decrypt(aes_key, receivedBytes)
            pt_message = bytes.decode(pt_bytes)
            print("From server: ", pt_message)
        elif mode == "CBC":
            pt_bytes = Encrypt_Decrypt.cbc_decrypt(aes_key, iv, receivedBytes)
            pt_message = bytes.decode(pt_bytes)
            print("From server: ", pt_message)
        else:
            print("Error: decrypt modes")
    else:
        connectionSocket.close()
        continueFlag = False


