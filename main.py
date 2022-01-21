# -*- coding: utf-8 -*-
"""
Created on Thu Jan 19 06:40:55 2022

@author: yosra
"""
from auth import signUp, signIn
import sys

def main():
    global username
        
    while True:
        # Phase 1 : Registration
        print("\tPhase 1 : Registration\n")
        signUp()
        
        # Phase 2 : Log in
        print("\n\tPhase 2 : Sign In\n")
        username, port = signIn() # User is connected and registered in the key server
        
        # Phase 3 : Cryptography tools + Chatroom
        print("\n\tPhase 3 : Cryptography tools + Secure chatroom\n")
        print("1- Encoding/Decoding")
        print("2- Hashing/Cracking Hashed Password")
        print("3- Symmetric Encryption/Decryption")
        print("4- Asymmetric Encryption/Decryption")
        print("5- Secure Chatroom")
        print("6- Quit")
        
        choice = int(input("Your choice : ").strip())
        if choice == 1:
            manage_encoding()
        elif choice == 2:
            manage_hashing()
        elif choice == 3:
            manage_symmetric_encryption()
        elif choice == 4:
            manage_asymmetric_encryption(username)
        elif choice == 5:
            manage_secure_chatroom(username, port)
        else:
            sys.exit()

def manage_encoding():
    import encoding
    
    method = input("PLease choose a base : UTF8, ASCII, Base64, Base32 or Base16 \n_ : ").strip()
    if method.lower() not in ['utf8', 'ascii', 'base64', 'base32', 'base16']:
        raise Exception('Invalid base !')
    
    print("1- Encode\n")
    print("2- Decode\n")
    choice = int(input("Your choice ? : ").strip())
    
    msg = input("Your message ? : ")
    if choice == 1:
        result = getattr(encoding, 'encode_'+method.lower())(msg)
    elif choice == 2:
        result = getattr(encoding, 'decode_'+method.lower())(msg)
    else:
        raise Exception('Invalid choice !')
    
    print('The result is : ',result)  
    
def manage_hashing():
    import hashing
    
    algorithm = input("PLease choose an algorithm : MD5, SHA1, SHA244, SHA256, SHA384, SHA512, BLAKE2B or BLAKE2S \n_ : ").strip()
    if algorithm.lower() not in ['md5', 'sha1', 'sha244', 'sha256', 'sha384', 'sha512', 'blake2b', 'blake2s']:
        raise Exception('Invalid algorithm !')
        
    print("1- Hash\n")
    print("2- Crack\n")
    choice = int(input("Your choice ? : ").strip())
    
    msg = input("Your message ? : ")
    if choice == 1:
        print('The hash is : ',hashing.hash_text(msg, algorithm))
    elif choice == 2:
        cracked_password = hashing.dictionary_attack(msg, algorithm)
        if cracked_password is not None:
            print("The password is : ", cracked_password)
    else:
        raise Exception('Invalid choice !')

    
def manage_symmetric_encryption():
    import symmetric_encryption
    
    algorithm = input("PLease choose an algorithm : AES or DES \n_ : ").strip()
    if algorithm.lower() not in ['aes', 'des']:
        raise Exception('Invalid algorithm !')
    
    print("1- Encrypt\n")
    print("2- Decrypt\n")
    choice = int(input("Your choice ? : ").strip())
    
    msg = input("Your message ? : ")
    key = input("Your key ? : ")
    if choice == 1:
        print('The encrypted data is : ',getattr(symmetric_encryption, 'encrypt_'+algorithm.lower())(msg, key).decode())
    elif choice == 2:
        print('The decrypted data is : ',getattr(symmetric_encryption, 'decrypt_'+algorithm.lower())(msg.encode(), key))
    else:
        raise Exception('Invalid choice !')
    
def manage_asymmetric_encryption(username):
    import asymmetric_encryption
    
    algorithm = input("PLease choose an algorithm : RSA or ElGamal \n_ : ").strip()
    if algorithm.lower() not in ['rsa', 'elgamal']:
        raise Exception('Invalid algorithm !')
    if algorithm.lower() == 'rsa':
        print("1- Generate Key Pair\n")
        print("2- Encrypt\n")
        print("3- Decrypt\n")
        choice = int(input("Your choice ? : ").strip())
        
        if choice == 1:
            pubkey, privkey = asymmetric_encryption.genkey_rsa()
            asymmetric_encryption.export_key_pair_rsa(username+"_test", pubkey, privkey)
            print("pubkey = ", pubkey,"\nprivkey = ", privkey,"\n")    
        elif choice == 2:
            msg = input("Your message ? : ") 
            pubkey = asymmetric_encryption.import_pubkey_rsa(username+"_test")
            print('The encrypted data is : ',getattr(asymmetric_encryption, 'encrypt_'+algorithm.lower())(msg, pubkey))
        elif choice == 3:        
            msg = input("Your message ? : ") 
            privkey = asymmetric_encryption.import_privkey_rsa(username+"_test")
            print('The decrypted data is : ',getattr(asymmetric_encryption, 'decrypt_'+algorithm.lower())(msg, privkey))
        else:
            raise Exception('Invalid choice !')
    elif algorithm.lower() == 'elgamal':
        pubkey, privkey = asymmetric_encryption.genkey_elgamal()
        encrypted_data = asymmetric_encryption.encrypt_elgamal(input("Data to encrypt ? : "), pubkey)
        print("Encrypted data is : ", encrypted_data)
        print("Decrypted data is : ", asymmetric_encryption.decrypt_elgamal(encrypted_data, privkey))
        
def manage_secure_chatroom(username, port):
    from chatroom import chat
    
    chat(username, port)
    
    
if __name__ == '__main__':
    main()
