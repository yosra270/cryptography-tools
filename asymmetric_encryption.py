# -*- coding: utf-8 -*-
"""
Created on Thu Jan 14 12:17:58 2022

@author: yosra
"""
import rsa
from elgamal import elgamal

# Asymmetric encryption : RSA & ElGamal 

# RSA
def genkey_rsa():  
    (pubkey, privkey) = rsa.newkeys(2048)    
    return (pubkey, privkey)

def export_key_pair_rsa(userID, pubkey, privkey): 
    # Save private and pub key
    with open('public_key_rsa_%s.pem' % userID, 'w+') as fp:
        fp.write(pubkey.save_pkcs1().decode())

    with open('private_key_rsa_%s.pem' % userID, 'w+') as fp:
        fp.write(privkey.save_pkcs1().decode())


def import_pubkey_rsa(userID):
    with open('public_key_rsa_%s.pem' % userID, 'r+') as fp:        
        pubkey = rsa.PublicKey.load_pkcs1(fp.read().encode())
    return pubkey

def import_privkey_rsa(userID):
    with open('private_key_rsa_%s.pem' % userID, 'r+') as fp:        
        privkey = rsa.PrivateKey.load_pkcs1(fp.read().encode())
    return privkey
        

def encrypt_rsa(data, public_key):
    return rsa.encrypt(data.encode(), public_key).hex()

def decrypt_rsa(encrypted_data, private_key):
    return rsa.decrypt(bytes.fromhex(encrypted_data), private_key).decode()

def sign_rsa(data, private_key):
    signature = rsa.sign(data.encode(), private_key, 'SHA-256')
    return signature

def verify_signature_rsa(data, signature, public_key):
    try:
        rsa.verify(data.encode(), signature, public_key)
    except rsa.pkcs1.VerificationError:
        return False
    return True

# ElGamal
def genkey_elgamal():
    key_pair = elgamal.generate_keys(256)
    (pubkey, privkey) = key_pair['publicKey'], key_pair['privateKey'] 
    return (pubkey, privkey)        

def encrypt_elgamal(data, public_key):
    return elgamal.encrypt(public_key, data)

def decrypt_elgamal(encrypted_data, private_key):
    return elgamal.decrypt(private_key, encrypted_data)

def test_elgamal():
    pubkey, privkey = genkey_elgamal()
    encrypted_data = encrypt_elgamal(input("Data to encrypt ? : "), pubkey)
    print("Encrypted data is : ", encrypted_data)
    print("Decrypted data is : ", decrypt_elgamal(encrypted_data, privkey))

#test_elgamal()