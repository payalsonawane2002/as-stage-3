import socket
import tkinter as tk
import threading
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


def decrypt_message(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()


def load_client_private_key():
    with open("client_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def send_message():
    client_message = client_message_entry.get()
    if client_message:
        encrypted_client_message = encrypt_message(client_message, server_public_key)
        print("-----------:Encrypted server message:--------------")
        print(encrypted_client_message)
        print("------------------:end:---------------------")
        s.sendall(len(encrypted_client_message).to_bytes(4, 'big'))
        s.sendall(encrypted_client_message)
        client_message_entry.delete(0, tk.END)
        if client_message.lower() == "exit":
            root.quit()


def receive_message():
    while True:
        encrypted_server_message_length = int.from_bytes(s.recv(4), 'big')
        encrypted_server_message = s.recv(encrypted_server_message_length)
        if encrypted_server_message:
            decrypted_server_message = decrypt_message(encrypted_server_message, private_key)
            server_message_label.config(text="Server message: " + decrypted_server_message)
            if decrypted_server_message.lower() == "exit":
                root.quit()


def main():
   
    global s, private_key, server_public_key

    private_key = load_client_private_key()

    # Establish connection with server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 12345))

    
    # Send client's public key to server
    with open("client_public.pem", "rb") as key_file:
        client_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    s.sendall(client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # Receive server's public key
    server_public_key_pem = s.recv(4096)
    server_public_key = serialization.load_pem_public_key(
        server_public_key_pem,
        backend=default_backend()
    )

    # Start receiving messages in a separate thread
    receive_thread = threading.Thread(target=receive_message)
    receive_thread.daemon = True
    receive_thread.start()


# GUI
root = tk.Tk()
root.title("Global Bank Client GUI")

client_message_entry = tk.Entry(root, width=50)
client_message_entry.pack(pady=10)

send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack()

server_message_label = tk.Label(root, text="")
server_message_label.pack()

if __name__ == "__main__":
    main()
    root.mainloop()
