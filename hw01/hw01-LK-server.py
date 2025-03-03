# Created by Louis Kraimer

import socket
import os

def connecting():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ip = input("Please enter the server IP: ")
    port = int(input("Please enter the port to bind to: "))
    s.bind((ip,port))
    print("Waiting for a connection... *cue jeopardy theme*")
    s.listen(1)
    connection,address = s.accept()
    print("We're In! :) Connection established at",address)

    while True:
        command = input("Shell> ")
        if "seeya" in command:
            connection.send("seeya".encode())
            connection.close()
            break
        else:
            connection.send(command.encode())
            print(connection.recv(5000).decode())

def main():
    connecting()
main()