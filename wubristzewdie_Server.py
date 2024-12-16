import socket
import os
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import shutil

# Server configuration
HOST = '127.0.0.1'  # Server IP address
PORT = 12345       # Server port number

# RSA keys for server
server_key = RSA.generate(2048)  # Generate RSA key pair
server_private_key = server_key  # Private key for decrypting data
server_public_key = server_key.publickey()  # Public key for encrypting data

# Define error codes for standardized responses
ERROR_CODES = {
    1: "File not found",
    2: "Invalid Command",
    3: "Permission Denied",
    4: "Server Error"
}

# Encryption Utilities
def encrypt_message_aes(message, key):
    """Encrypts a message using AES encryption."""
    try:
        iv = os.urandom(16)  # Generate a random Initialization Vector (IV)
        cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher in CBC mode
        ct = cipher.encrypt(pad(message.encode(), AES.block_size))  # Encrypt with padding
        return base64.b64encode(iv + ct).decode()  # Encode IV and ciphertext in Base64
    except Exception as e:
        print(f"Encryption error: {e}")
        return message

def decrypt_message_aes(encrypted_message, key):
    """Decrypts a message using AES encryption."""
    try:
        raw_data = base64.b64decode(encrypted_message)  # Decode Base64 message
        iv, ct = raw_data[:16], raw_data[16:]  # Extract IV and ciphertext
        cipher = AES.new(key, AES.MODE_CBC, iv)  # Create AES cipher in CBC mode
        return unpad(cipher.decrypt(ct), AES.block_size).decode()  # Decrypt and remove padding
    except Exception as e:
        print(f"Decryption error: {e}")
        return encrypted_message

def encrypt_message_caesar(message, shift):
    """Encrypts a message using Caesar Cipher."""
    return ''.join(chr((ord(char) + shift - 32) % 95 + 32) if 32 <= ord(char) <= 126 else char for char in message)

def decrypt_message_caesar(encrypted_message, shift):
    """Decrypts a message using Caesar Cipher."""
    return ''.join(chr((ord(char) - shift - 32) % 95 + 32) if 32 <= ord(char) <= 126 else char for char in encrypted_message)

def execute_command(command_type, args, encryption=None, key=None):
    """Executes commands for file and folder management."""
    try:
        # Decrypt command and arguments if encryption is enabled
        if encryption == "Caesar":
            command_type = decrypt_message_caesar(command_type, key)
            args = [decrypt_message_caesar(arg, key) for arg in args]
        elif encryption == "AES":
            command_type = decrypt_message_aes(command_type, key)
            args = [decrypt_message_aes(arg, key) for arg in args]

        # Handle various file and directory commands
        if command_type == "mkdir":
            os.mkdir(args[0])  # Create directory
            response = "SC,Folder created successfully"
        elif command_type == "cd":
            os.chdir(args[0])  # Change current directory
            response = "SC,Directory changed successfully"
        elif command_type in ("rmdir", "rd"):
            os.rmdir(args[0])  # Remove directory
            response = "SC,Folder removed successfully"
        elif command_type == "del":
            os.remove(args[0])  # Delete file
            response = "SC,File deleted successfully"
        elif command_type == "ren":
            os.rename(args[0], args[1])  # Rename file or directory
            response = "SC,File renamed successfully"
        elif command_type == "openWrite":
            with open(args[0], 'w') as file:  # Open file for writing
                response = "SC,File opened for writing"
        elif command_type == "openRead":
            # Read content from the file
            with open(args[0], 'r') as file:  # Open file for reading
                content = file.read()

            # If the file is not empty, apply encryption (if needed)
            if content:  # If file has content
                if encryption == "Caesar":
                    content = encrypt_message_caesar(content, key)
                elif encryption == "AES":
                    content = encrypt_message_aes(content, key)
                response = f"SC,File contents: {content}"
            else:
                # If the file is empty, return an appropriate response without encryption
                response = "SC,File is empty"
        
        elif command_type == "ls":
            files = os.listdir('.')  # List files in the current directory
            response = f"SC,{', '.join(files)}"
        elif command_type == "pwd":
            cwd = os.getcwd()  # Get current working directory
            response = f"SC,Current directory: {cwd}"
        elif command_type == "touch":
            with open(args[0], 'w') as file:  # Create an empty file
                pass
            response = "SC,File created successfully"
        elif command_type == "filesize":
            size = os.path.getsize(args[0])  # Get size of the file
            response = f"SC,File size: {size} bytes"
        elif command_type == "copy":
            shutil.copy(args[0], args[1])  # Copy file
            response = "SC,File copied successfully"
        else:
            response = f"EE,2,Command not found"  # Invalid command

        # Encrypt response if encryption is enabled
        if command_type != "ls":
            if encryption == "Caesar":
                response = encrypt_message_caesar(response, key)
            if encryption == "AES":
                response = encrypt_message_aes(response, key)

        return response
    except FileNotFoundError:
        return f"EE,1,{ERROR_CODES[1]}"  # Handle file not found
    except PermissionError:
        return f"EE,3,{ERROR_CODES[3]}"  # Handle permission denied
    except Exception as e:
        return f"EE,4,{ERROR_CODES[4]} - {str(e)}"  # Generic server error

def handle_client(client_socket):
    """Handles client communication."""
    encryption = None  # Encryption method (AES or Caesar)
    key = None  # Encryption key

    try:
        while True:
            packet = client_socket.recv(1024).decode()  # Receive packet from client
            if not packet:
                break

            fields = packet.split(',')

            # Setup Phase: Handle Start Packet (SS)
            if fields[0] == "SS":
                secure_comm = int(fields[3])  # Check if secure communication is requested
                if secure_comm == 1:
                    # Send public key to client
                    client_socket.send(f"CC,{server_public_key.export_key().decode()}".encode())
                    # Receive encryption packet from client
                    encryption_packet = client_socket.recv(1024).decode().split(',')
                    rsa_cipher = PKCS1_OAEP.new(server_private_key)
                    encryption = encryption_packet[1]  # Get encryption method
                    if encryption == "Caesar":
                        key = int(rsa_cipher.decrypt(base64.b64decode(encryption_packet[2])).decode())
                    elif encryption == "AES":
                        key = rsa_cipher.decrypt(base64.b64decode(encryption_packet[2]))
                    client_socket.send("SC,Encryption setup successful".encode())
                else:
                    client_socket.send("CC".encode())  # Confirm plain communication

            # Command Execution Phase: Handle Command Packet (CM)
            elif fields[0] == "CM":
                if len(fields) < 2 or not fields[1].strip():
                    response = "EE,2,Please enter a valid command"
                else:
                    command_type = fields[1]  # Extract command type
                    args = fields[2:]  # Extract arguments

                    # General check for missing arguments (except ls, pwd)
                    if command_type not in ("ls", "pwd") and not args:
                        response = f"EE,2,Please enter your argument for the '{command_type}' command"
                    # Specific handling for openWrite
                    elif command_type == "openWrite":
                         if len(args) < 1:
                              response = "EE,2,File name not provided"
                         else:
                         # Decrypt the file name if encryption is enabled
                                if encryption is not None and key is not None:
                                     file_name = decrypt_message_aes(args[0], key) if encryption == "AES" else decrypt_message_caesar(args[0], key)
                                else:
                                    file_name = args[0]  # Use raw file name if no encryption
        
                                print(f"File name after decryption (if applicable): {file_name}")

                                # Confirm that the file is ready for writing
                                response = "SC,File opened for writing"
                                client_socket.send(response.encode())
                                print("Sent confirmation: File opened for writing")

                                # Receive data packet from the client in chunks and write to the file
                                try:
                                   with open(file_name, 'wb') as file:
                                       while True:
                                           data_packet = client_socket.recv(1024)
                                           if not data_packet:
                                                break
                                           print(f"Received data (before decryption): {data_packet}")
                                           if encryption is not None and key is not None:
                                              if encryption == "AES":
                                                data_packet = decrypt_message_aes(data_packet.decode(), key).encode()
                                              elif encryption == "Caesar":
                                                data_packet = decrypt_message_caesar(data_packet.decode(), key).encode()
                                           file.write(data_packet)

                                   print("Data written to the file successfully")
                                   client_socket.send("SC,Data written to file successfully".encode())
                                except Exception as write_error:
                                   client_socket.send(f"EE,4,Error writing to file: {str(write_error)}".encode())
                                   print(f"Error writing to file '{file_name}': {write_error}")
                                continue  # Skip further processing for this command

                    else:
                        # Handle other commands
                        response = execute_command(command_type, args, encryption, key)

                client_socket.send(response.encode())  # Send response to client

            # Closing Phase: Handle End Packet
            elif fields[0] == "End":
                print("End packet received. Closing connection...")
                client_socket.send("SC,Server shutting down.".encode())
                break

    except Exception as e:
        client_socket.send(f"EE,4,{ERROR_CODES[4]} - {str(e)}".encode())  # Send error packet
    finally:
        client_socket.close()  # Close client connection


def start_server():
    print(" \n******* Welcome to Remote File Management Protocol (RFMP)! ********\n")
    """Starts the server with multithreading."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Server starting....\nServer listening on {HOST} : {PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}") # accepting client connection 
        client_thread = threading.Thread(target=handle_client, args=(client_socket,)) # creat new thread
        client_thread.start() # starts new thread

if __name__ == "__main__":
    start_server()
