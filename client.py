# Client program
# Connects to the server at port 7777
# Sends a message to the server, receives a reply and closes the connection
# Use Python 3 to run

import socket
from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE,SIG_DFL)

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

continueFlag = True
while continueFlag:
    # Takes input from user to send to server
    userInput = input("Please enter a message to send to the server: "
                      "(enter 'bye' to exit)")
    # check whether input is exit message
    if userInput != "bye":
        # Encode the message into bytes
        messageBytes = userInput.encode()

        # Send the bytes through the connection socket
        connectionSocket.send(messageBytes)

        # Receive the message from the server (receive no more than 1024 bytes)
        receivedBytes = connectionSocket.recv(1024)

        # Decode the bytes into a string (Do this only for strings, not keys)
        receivedMessage = bytes.decode(receivedBytes)
        # Print the message
        print("From server: ", receivedMessage)
    else:
        connectionSocket.close()
        continueFlag = False


