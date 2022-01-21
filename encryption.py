# -*- coding: utf-8 -*-
"""
Created on Thu Jan 14 06:40:03 2022

@author: yosra
"""
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES, DES


# Symmetric encryption : DES & AES256
def encrypt_aes(data, key):
    key = hashlib.sha256(key.encode()).digest()
    # Unique initialization_vector per encrypted file
    ''' (from StackOverflow) If you had no IV, and used chained block encryption with just your key, 
    two files that begin with identical text will produce identical first blocks. 
    If the input files changed midway through, then the two encrypted files would begin to look different beginning at that point and through to the end of the encrypted file. 
    If someone noticed the similarity at the beginning, and knew what one of the files began with, he could deduce what the other file began with. 
    Knowing what the plaintext file began with and what it's corresponding ciphertext is could allow that person to determine the key and then decrypt the entire file.
    '''    
    initialization_vector = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, initialization_vector)
    return base64.b64encode(initialization_vector + cipher.encrypt(data.encode()))

def decrypt_aes(coded_data, key):
    key = hashlib.sha256(key.encode()).digest()
    coded_data = base64.b64decode(coded_data)
    iv = coded_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(coded_data[AES.block_size:]).decode('utf-8')

def encrypt_des(data, key):
    key = hashlib.sha256(key.encode()).digest()
    # Unique initialization_vector per encrypted file
    ''' (from StackOverflow) If you had no IV, and used chained block encryption with just your key, 
    two files that begin with identical text will produce identical first blocks. 
    If the input files changed midway through, then the two encrypted files would begin to look different beginning at that point and through to the end of the encrypted file. 
    If someone noticed the similarity at the beginning, and knew what one of the files began with, he could deduce what the other file began with. 
    Knowing what the plaintext file began with and what it's corresponding ciphertext is could allow that person to determine the key and then decrypt the entire file.
    '''    
    initialization_vector = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, initialization_vector)
    return base64.b64encode(initialization_vector + cipher.encrypt(data.encode()))

def decrypt_des(coded_data, key):
    key = hashlib.sha256(key.encode()).digest()
    coded_data = base64.b64decode(coded_data)
    iv = coded_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(coded_data[AES.block_size:]).decode('utf-8')

# Asymmetric encryption : RSA & ElGamal 