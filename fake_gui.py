import socket
import tkinter as tk
from threading import Thread
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def encrypt_message(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def load_server_public_key():
    try:
        with open("hacked_key.pem", "rb") as key_file:  # Load the correct server's public key
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        print(f"Error loading public key: {e}")
        return None

def send_message():
    client_message = entry.get()

    encrypted_client_message = encrypt_message(client_message, public_key)

    # Send length of data before sending actual data
    s.sendall(len(encrypted_client_message).to_bytes(4, 'big'))
    s.sendall(encrypted_client_message)

    if client_message.lower() == "exit":
        root.quit()

def receive_messages():
    while True:
        encrypted_server_message_length = int.from_bytes(s.recv(4), 'big')
        encrypted_server_message = s.recv(encrypted_server_message_length)

        if not encrypted_server_message:
            return
        
        print("-----------:Encrypted server message:--------------")
        print(encrypted_server_message)
        print("------------------:end:---------------------")

public_key = load_server_public_key()
if not public_key:
    exit()

# Establish connection with server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 12345))

root = tk.Tk()
root.title("Client")

entry = tk.Entry(root, width=50)
entry.pack(pady=10)

send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack()

label = tk.Label(root, text="")
label.pack(pady=10)

# Start a thread to continuously receive messages from the server
receive_thread = Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

root.mainloop()
