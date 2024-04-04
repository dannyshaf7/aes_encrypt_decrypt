# Client program
# Connects to the server at port 7777
# Sends a message to the server, receives a reply and closes the connection
# Use Python 3 to run
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import math
import socket
from signal import signal, SIGPIPE, SIG_DFL
import sys
import time


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
        return False, None, None


def fragment_message(message):
    frag_count = math.ceil(len(message) / 1020)
    # print("Number of fragments: ", frag_count)
    msg_length = frag_count.to_bytes(2, 'big', signed=False)
    connection_socket.send(msg_length)
    time.sleep(0.01)
    byte_start = 0
    byte_end = 1020
    count = 0
    for i in range(frag_count, 0, -1):
        count_bytes = count.to_bytes(4, byteorder="big")
        frag_msg = count_bytes + message[byte_start:byte_end]
        count += 1
        byte_start += 1020
        byte_end += 1020
        connection_socket.send(frag_msg)
        time.sleep(0.01)


signal(SIGPIPE, SIG_DFL)
# create a socket object
connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# get local machine name
host = socket.gethostname()
# This port is where the server is listening
port = 7777
# connect to hostname on the port. Note that (host,port) is a tuple.


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
        print("key generated: ", aes_key, "\n")
        connection_socket.connect((host, port))
        connection_socket.send(aes_key)
        time.sleep(0.01)
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
            cipher = AES.new(aes_key, AES.MODE_ECB)
            ct_bytes = cipher.encrypt(pad(messageBytes, AES.block_size))
            ct_string = ct_bytes.decode(encoding="utf-8", errors="ignore")
            # print("key: ", aes_key, "\nencrypted text: ", ct_string, "\n")
            # Send the bytes through the connection socket
            # print(ct_bytes)
            if len(ct_bytes) > 1024:
                fragment_message(ct_bytes)
            else:
                frag_count = 1
                # print("Number of fragments: ", frag_count)
                msg_length = frag_count.to_bytes(2, 'big', signed=False)
                # print(msg_length)
                connection_socket.send(msg_length)
                time.sleep(0.01)
                connection_socket.send(ct_bytes)
        elif mode == "cbc":
            iv = get_random_bytes(AES.block_size)
            connection_socket.send(iv)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            ct_bytes = cipher.encrypt(pad(messageBytes, AES.block_size))
            ct_string = ct_bytes.decode(encoding="utf-8", errors="ignore")
            # print("key: ", aes_key, "\niv: ", iv, "\nencrypted text: ", ct_string, "\n")
            # Send the bytes through the connection socket
            if len(ct_bytes) > 1024:
                fragment_message(ct_bytes)
            else:
                frag_count = 1
                # print("Number of fragments: ", frag_count)
                msg_length = frag_count.to_bytes(2, 'big', signed=False)
                # print(msg_length)
                connection_socket.send(msg_length)
                time.sleep(0.01)
                connection_socket.send(ct_bytes)
            # connection_socket.send(ct_bytes)
        else:
            print("Error: encrypt modes")
            connection_socket.close()
        # Receive the message from the client (receive no more than 1024 bytes)
        frag_num = connection_socket.recv(1024)
        # print(frag_num)
        # if there is no value for received bytes, no longer connected to client so break the while loop
        # if not msg_received:
        if not frag_num:
            break
        else:
            msg_received = b''
            frag_list = []
            frag_num = int.from_bytes(frag_num, 'big', signed=False)
            # print("Number of fragments: ", frag_num)
            if frag_num > 1:
                for i in range(0, frag_num):
                    msg_received = connection_socket.recv(1024)
                    # print(msg_received)
                    seq_bytes = msg_received[:4]
                    seq_num = int.from_bytes(seq_bytes, byteorder='big')
                    # print("sequence number: ", seq_num)
                    frag_list.insert(seq_num, msg_received[4:])
                    msg_received = b''
                    # print(frag_list)
                # print(frag_list)
                for j in range(0, len(frag_list)):
                    # print(j, ": ", frag_list[j])
                    msg_received += frag_list[j]
                    # print(msg_received)
                # print(msg_received)
                time.sleep(0.01)
            else:
                msg_received = connection_socket.recv(1024)
        # msg_received = connection_socket.recv(1024)
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
