# -*- coding: utf-8 -*-
"""
Created on Thu Jan 14 06:40:40 2022

@author: yosra
"""
from socket import socket, gethostname, AF_INET, SOCK_STREAM, error
from hashing import generate_secure_password
from symmetric_encryption import encrypt_aes, decrypt_aes
from asymmetric_encryption import encrypt_rsa, decrypt_rsa, import_privkey_rsa, import_pubkey_rsa
import sys


def chat(username, port): 
    # Choose peer from the key server : public key + port number
    print("Please choose a peer to chat with : ")
    with open('key_server.txt', 'r+') as key_server:        
        for line in key_server.readlines():
            username_peer = line.split()[0]
            if username_peer != username:
                print(username_peer + '\n')
    
    choice = input("_ : ").strip()     
    
    # Find the peer's port and public key
    with open('key_server.txt', 'r+') as key_server:        
        for line in key_server.readlines():
            if choice in line:
                USERNAME_PEER = line.split()[0]
                PORT_PEER = int(line.split()[1])
                #PUBLIC_KEY_PEER_PEM_FILE_IDENTIFIER = line.split()[2].strip().encode()
                PUBLIC_KEY_PEER = import_pubkey_rsa(USERNAME_PEER)
                break
        if USERNAME_PEER is None:
            print("Wrong username provided !")
            sys.exit()
    try:
        # If peer's server is up, connect as a client
        send_msg(PORT_PEER, PUBLIC_KEY_PEER)
        # Then wait for their reply
        chat_server(username, port, USERNAME_PEER, PORT_PEER, PUBLIC_KEY_PEER)
    except error:
        # Listen to peer's messages
        print("Waiting for your friend to enter the chatroom ...")
        chat_server(username, port, USERNAME_PEER, PORT_PEER, PUBLIC_KEY_PEER)
    
def chat_server(username, port, USERNAME_PEER, PORT_PEER, PUBLIC_KEY_PEER):
    # Prepare server's socket and listen for other users
    server_socket = socket(AF_INET, SOCK_STREAM) # INET => IPv4; STREAM => TCP
    server_socket.bind((gethostname(), port))
    
    server_socket.listen(5)
    while True:
        # Establish connection with client
        connection, address = server_socket.accept()         
        
        # Wait for peer's message
        encrypted_message, encrypted_symmetric_key = connection.recv(4096).decode().splitlines() # Buffer's size is up to 4096 bytes
        
        # Decode the message
        symmetric_key = decrypt_rsa(encrypted_symmetric_key, import_privkey_rsa(username))
        message = decrypt_aes(encrypted_message, symmetric_key)
        
        print("\n", USERNAME_PEER, " : ", message)
            
        connection.close()
        
        # Reply as a client of the peer's socket server
        send_msg(PORT_PEER, PUBLIC_KEY_PEER)

def send_msg(PORT_PEER, PUBLIC_KEY_PEER):
    # Prepare socket
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect((gethostname(), PORT_PEER))
    
    message = input("_ : ")
    
    ''' We are going to combine RSA encryption with AES symmetric encryption to achieve the security of RSA with the performance of AES. 
    This is normally done by generating a temporary, or session, AES key and protecting it with RSA encryption. 
    => Hybrid cryptosystem
    '''
    # Encrypt message 
        # Data encapsulation scheme ( symmetric-key cryptosystem ) => The encryption/decryption of messages that can be very long is done by the more efficient symmetric-key scheme
    symmetric_key = generate_secure_password()
    encrypted_message = encrypt_aes(message, symmetric_key)
    
        # Key encapsulation scheme ( public-key cryptosystem ) => Inefficient public-key scheme is used only to encrypt/decrypt a short key value
    encrypted_symmetric_key = encrypt_rsa(symmetric_key, PUBLIC_KEY_PEER)
    
    # Send encrypted message
    client_socket.send((encrypted_message.decode()+"\n"+ encrypted_symmetric_key).encode())
    
    # Close socket
    client_socket.close()
