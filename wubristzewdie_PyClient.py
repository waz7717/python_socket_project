import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

# Client configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
AES_SESSION_KEY = b'sixteen_byte_key'  # 16-byte AES session key
CAESAR_SHIFT = 5  # Caesar Cipher shift value

def decrypt_message_aes(encrypted_message, key):
    """Decrypts a message using AES."""
    try:
        # Ensure the key is valid for AES (16, 24, or 32 bytes)
        assert len(key) in [16, 24, 32], "Invalid AES key length"
        
        # Decode the base64-encoded encrypted message
        raw_data = base64.b64decode(encrypted_message)
        
        # Extract the IV (first 16 bytes) and ciphertext
        iv, ct = raw_data[:16], raw_data[16:]
        
        # Initialize cipher with key and IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt and unpad the ciphertext
        return unpad(cipher.decrypt(ct), AES.block_size).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return encrypted_message  # Return raw message if decryption fails



def encrypt_message_aes(message, key):
    """Encrypts a message using AES."""
    try:
        # Ensure the key is valid for AES (16, 24, or 32 bytes)
        assert len(key) in [16, 24, 32], "Invalid AES key length"
        
        # Generate a random 16-byte IV
        iv = os.urandom(16)
        
        # Initialize cipher with key and IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Encrypt the message with padding
        ct = cipher.encrypt(pad(message.encode(), AES.block_size))
        
        # Combine IV and ciphertext and return base64 encoded
        return base64.b64encode(iv + ct).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return message  # Return raw message if encryption fails

def encrypt_message_caesar(message, shift):
    """Encrypts a message using Caesar Cipher."""
    encrypted = ''.join(
        chr((ord(char) + shift - 32) % 95 + 32) if 32 <= ord(char) <= 126 else char
        for char in message
    )
    return encrypted


def decrypt_message_caesar(encrypted_message, shift):
    """Decrypts a message using Caesar Cipher."""
    decrypted = ''.join(
        chr((ord(char) - shift - 32) % 95 + 32) if 32 <= ord(char) <= 126 else char
        for char in encrypted_message
    )
    return decrypted
def handle_open_read(file_name, client, secure_comm, session_key):
    """Sends openRead command and handles the server response."""
    if secure_comm:
        encrypted_command = encrypt_message_aes("openRead", session_key)
        encrypted_file = encrypt_message_aes(file_name, session_key)
        client.send(f"CM,{encrypted_command},{encrypted_file}".encode())
    else:
        client.send(f"CM,openRead,{file_name}".encode())

    response = client.recv(1024).decode()
    if secure_comm:
        response = decrypt_message_aes(response, session_key)
    print(f"Server Response: {response}")
    
def handle_open_write(file_name, client, secure_comm, session_key):
    """Sends openWrite command and sends data packets."""
    # Send the openWrite command and file name to the server
    if secure_comm:
        encrypted_command = encrypt_message_aes("openWrite", session_key)
        encrypted_file = encrypt_message_aes(file_name, session_key)
        client.send(f"CM,{encrypted_command},{encrypted_file}".encode())
    else:
        client.send(f"CM,openWrite,{file_name}".encode())

    # Receive confirmation from the server that the file has been opened for writing
    response = client.recv(1024).decode()
    print(f"Server Response: {response}")

    if response.startswith("SC,File opened for writing"):
        # Sample data to write to the file
        data = "Sample data sent for testing"

        # Send the data packet to the server
        if secure_comm:
            encrypted_data = encrypt_message_aes(data, session_key)
            client.send(f"DP,{encrypted_data}".encode())
        else:
            client.send(f"DP,{data}".encode())

        # Receive confirmation for the data packet from the server
        response = client.recv(1024).decode()
        print(f"Server Response: {response}")
def start_client():
    print(" \n********* Welcome to Remote File Management Protocol (RFMP)! ********\n")
    """Starts the client."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((SERVER_HOST, SERVER_PORT))

    while True:
        secure_comm_input = input("Enable encryption? (yes/no): ").strip().lower()
        
        # Validate encryption enable input
        if secure_comm_input in ("yes", "no"):
            break
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")
    secure_comm = secure_comm_input == "yes"
    encryption_method = None

    if secure_comm:
        # Choose encryption method
        while True:
            encryption_method = input("Choose encryption method (AES/Caesar): ").strip()
            if encryption_method in ("AES", "Caesar"):
                break
            else:
                print("Invalid encryption method. Please choose either 'AES' or 'Caesar'.")

        # Send Start Packet
        client.send("SS,RFMP,v1.0,1".encode())
        response = client.recv(1024).decode().split(',')
        server_public_key = RSA.import_key(response[1])

        # Encrypt session key
        rsa_cipher = PKCS1_OAEP.new(server_public_key)
        if encryption_method == "AES":
            encrypted_session_key = base64.b64encode(rsa_cipher.encrypt(AES_SESSION_KEY)).decode()
        elif encryption_method == "Caesar":
            encrypted_session_key = base64.b64encode(rsa_cipher.encrypt(str(CAESAR_SHIFT).encode())).decode()

        # Send Encryption Packet
        client.send(f"EC,{encryption_method},{encrypted_session_key}".encode())
        print(client.recv(1024).decode())  # Encryption confirmation
    else:
        client.send("SS,RFMP,v1.0,0".encode())
        print(client.recv(1024).decode())  # Connection confirmation

    try:
        while True:
            command = input("Enter command (or 'exit' to quit): ").strip()

            # Check for empty command
            if not command:
                print("Empty command. Please enter your command.")
                continue
            if command.strip().lower() == "exit":
                client.send("End".encode())
                print("Closing connection...")
                break

            command_fields = command.split()
            valid_commands = [
                "ls", "pwd", "mkdir", "cd", "rmdir", "rd", "del", "ren", 
                "openWrite", "openRead", "touch", "filesize", "copy"
            ]

            # Check if the command is valid
            if command_fields[0] not in valid_commands:
               print("EE,2,Invalid command. Please enter a valid command.")
               continue

            # Check for commands that require arguments
            if len(command_fields) == 1 and command_fields[0] not in ("ls", "pwd"):
                print(f"Missing argument for the '{command_fields[0]}' command. Please provide the necessary argument(s).")
                continue

            # Encrypt command if secure communication is enabled
            if secure_comm:
                if encryption_method == "AES":
                    encrypted_command = encrypt_message_aes(command_fields[0], AES_SESSION_KEY)
                    encrypted_args = [encrypt_message_aes(arg, AES_SESSION_KEY) for arg in command_fields[1:]]
                elif encryption_method == "Caesar":
                    encrypted_command = encrypt_message_caesar(command_fields[0], CAESAR_SHIFT)
                    encrypted_args = [encrypt_message_caesar(arg, CAESAR_SHIFT) for arg in command_fields[1:]]

                client.send(f"CM,{encrypted_command},{','.join(encrypted_args)}".encode())
            else:
                client.send(f"CM,{command_fields[0]},{','.join(command_fields[1:])}".encode())

            # Receive response from server
            response = client.recv(1024).decode()

            # Skip decryption for `ls` command (plaintext response)
            if command_fields[0] == "ls":
                print(f"Server Response: {response}")
            else:
                # Decrypt response if secure communication is enabled
                if secure_comm:
                    if encryption_method == "AES":
                        response = decrypt_message_aes(response, AES_SESSION_KEY)
                    elif encryption_method == "Caesar":
                        response = decrypt_message_caesar(response, CAESAR_SHIFT)

                print(f"Server Response: {response}")

    finally:
        client.close()



if __name__ == "__main__":
    start_client()
