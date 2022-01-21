# -*- coding: utf-8 -*-
"""
Created on Thu Jan 14 09:23:56 2022

@author: yosra
"""
import hashlib
import secrets
import string
from random import randint

# Hashing : MD5, SHA1, SHA244, SHA256, SHA384, SHA512, BLAKE2B and BLAKE2S
def hash_text(text, algorithm): 
    return getattr(hashlib, algorithm.lower())(text.encode()).hexdigest()
        
# Suggest secure password
def generate_secure_password():    
    alphabet = string.ascii_letters + string.digits + string.punctuation # Upper and lower case letters + digits + special characters
    password = ''.join(secrets.choice(alphabet) for i in range(randint(8,64)))
    
    return password

# Cracking hashes : Birthday Attack, Dictionary Attack & Brute Force     
def dictionary_attack(hashed_password, algorithm):
    wordlist = open("rockyou.txt")
    
    with open("rockyou.txt", mode='r+' , encoding="ANSI") as wordlist:
        for potential_password in wordlist.readlines():
            potential_password_hash = hash_text(potential_password.rstrip("\n"), algorithm)
            if potential_password_hash == hashed_password:
                return potential_password
        
    return None

#print(hash_text('test', 'sha256'))
#print(dictionary_attack('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 'sha256'))

#def birthday_attack(hashed_password):
#def brute_force_attack(hashed_password):
    
