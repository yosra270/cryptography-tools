# -*- coding: utf-8 -*-
"""
Created on Sat Jan 13 13:26:10 2022

@author: yosra
"""
from mongoengine import connect, Document, StringField, IntField
import sys
import re
import pwnedpasswords
from getpass import getpass
from random import randint
import time
from validate_email import validate_email as is_email_address_real
from asymmetric_encryption import genkey_rsa, export_key_pair_rsa

ACCOUNT_LOCKOUT_THRESHOLD = 3
MAX_PASSWORD_CONFIRMATION_ATTEMPTS = 5

# Connect to the DB
connect('cryptogrpahy-tools', host='localhost', port=27017)

class User(Document) :    
    username = StringField(required=True)
    email = StringField(required=True)
    password = StringField(required=True)
    failed_logins_counter = IntField(default=0)
    
def validate_email(entered_email) :
    # Check if this address is a real one 
    is_email_address_valid = is_email_address_real(entered_email,verify=True)
    if is_email_address_valid is False:
        return validate_email(input("Please enter your real email address! : "))
    else:           
        # Check if an account with this email already exists
        does_account_already_exists = True if User.objects(email=entered_email).count() != 0 else False
        if does_account_already_exists is True :
            print("You already have an account !")
            return None
        return entered_email
    
def validate_username(entered_username):
    if re.match("^[a-zA-Z0-9_.-]+$", entered_username) is None:
        print("Your username should contains only letters, digits, ., - or _ !")
        return validate_username(input("Please choose another one ! : "))
    else:
        # Check if an account with this username already exists
        is_username_already_exists = True if User.objects(username=entered_username).count() != 0 else False
        if is_username_already_exists is True :
            print("This username is already in use.")
            return validate_username(input("Please choose another one ! : "))
        else :
            return entered_username

def validate_passwd(entered_password):
    ''' Password length should be no shorter than 8 characters (otherwise they are considered weak).
     It is important to set a maximum password length to prevent long password Denial of Service attacks.
     A common maximum length is 64 characters due to limitations in certain hashing algorithms. 
     Password should include at least a digit number, a upcase and a lowcase letter and a special characters
    '''
    pattern = re.compile('^(?=\S{8,64}$)(?=.*?\d)(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])')  
    
    if pattern.search(entered_password) is None:
        print("Your password should be between 8 and 64 characters. It should include at least a digit number, a upcase and a lowcase letter and a special character.")
        return validate_passwd(input("Wanna try another password ? :"))
    else:
        # Check if passwd is pwned
        '''
        Pwned Passwords are hundreds of millions of real world passwords previously exposed in data breaches. 
        This exposure makes them unsuitable for ongoing use as they're at much greater risk of being used to take over other accounts.
        '''
        
        '''
        pwnedpasswords checks if a passphrase has been pwned using the Pwned Passwords v2 API. 
        All provided password data is k-anonymized before sending to the API, so plaintext passwords would never be sent.
        '''
        is_passwd_pwned = True if pwnedpasswords.check(entered_password) > 0 else False
        
        if is_passwd_pwned is True:
            print("You have been pwned !")
            return validate_passwd(input("Wanna try another password ? :"))
        else:
            double_entered_password = input("Please confirm your password : ")
            password_confirmation_attempts = 1
            while double_entered_password != entered_password and password_confirmation_attempts < MAX_PASSWORD_CONFIRMATION_ATTEMPTS:
                double_entered_password = input("Please confirm your password : ")
                password_confirmation_attempts = password_confirmation_attempts + 1
                
            if password_confirmation_attempts >= MAX_PASSWORD_CONFIRMATION_ATTEMPTS:
                sys.exit()
                
            return entered_password
    
def hash_password(password):
    from argon2 import PasswordHasher
    
    ''' 
    Password hashed using  Argon2id with a minimum configuration of :
        15 MiB of memory
        an iteration count of 2
        and 1 degree of parallelism
    As recommended by OWASP
    '''
    hash = PasswordHasher(memory_cost = 15360, time_cost = 2, parallelism = 1, salt_len = 16).hash(password)
    return hash

def send_auth_email(recipient_email_address, secret_code):
    import smtplib , ssl  
    
    port = 587  # For starttls
    smtp_server = "smtp.gmail.com"
    sender_email = 'dyosra892@gmail.com'
    sender_password = 'iOv_12345678'   
    
    message = f"""\
Subject: Verification code

    Hello ! This is your secret code: {secret_code} """
    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls(context=context)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email_address, message)
        
def register_in_key_server(username, port): 
    # Create private and public key 
    pubkey, privkey = genkey_rsa()
    export_key_pair_rsa(username, pubkey, privkey)
    # Register the user in the key server with its public key and port number
    pubkey_pem_file_identifier = 'private_key_rsa_%s.pem' % username
    with open('key_server.txt', 'a') as key_server:
        key_server.write(username+" "+str(port)+" "+pubkey_pem_file_identifier+'\n')
    
def signUp() :
    # Ask for user's data : 
    # username (must be unique) 
    email = validate_email(input("email : "))
    if email is None: # User has already an account
        return
    
    # email address(must be a real one and unique in the database)
    username = validate_username(input("username : "))
    # password (must be strong)
    password = validate_passwd(getpass("password : "))
    
    # Add user to the database (with password hashed)
    User(
        email = email,
        username = username,
        password = hash_password(password),
    ).save()

def signIn() :
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    waiting_till_next_login = 0 # in seconds
    
    name_entered = input("Your username or your email ? : ")
    password_entered = getpass("Your password ? : ")
    
    # Verify that the user exists + password is correct
    user = User.objects(username=name_entered) if len(User.objects(username=name_entered)) > 0 else User.objects(email=name_entered)
    if len(user) > 0:
        user = user[0]
    else:
        user = None
    are_credentials_correct = False if user is None else True
    if user is not None:     
        password_hasher = PasswordHasher(memory_cost = 15360, time_cost = 2, parallelism = 1, salt_len = 16)
        try:
            is_password_correct = password_hasher.verify(user.password, password_entered)
        except VerifyMismatchError:
            is_password_correct = False
            
        are_credentials_correct = True if is_password_correct is True else False
        # Account lockout mechanism
        if is_password_correct is False:
            user = User.objects(username=user.username).modify(inc__failed_logins_counter=1)
            print(user.failed_logins_counter)
            if user.failed_logins_counter >= ACCOUNT_LOCKOUT_THRESHOLD:
                waiting_till_next_login = 2**user.failed_logins_counter
        
    
    if are_credentials_correct is False:
        # Generic error message
        print("Invalid Username or Password!")
        if waiting_till_next_login > 0:
            print("Your account is locked. You will be able to login in ", waiting_till_next_login, " seconds")
            time.sleep(waiting_till_next_login)
        signIn()
    else:
        # Two-factor authentication : send secret code of 6 digits in an email
        secret_code = randint(10**5, 10**6-1)
        send_auth_email(user.email, secret_code)
        entered_secret_code = int(input("We've sent you a secret code of 6 digits on your email. Please type it ? :"))
        if entered_secret_code != secret_code:
            user = User.objects(username=user.username).modify(inc__failed_logins_counter=1)
            if user.failed_logins_counter >= ACCOUNT_LOCKOUT_THRESHOLD:
                waiting_till_next_login = 2**user.failed_logins_counter
            print("Invalid Code!")
            if waiting_till_next_login > 0:
                print("Your account is locked. You will be able to login in ", waiting_till_next_login, " seconds")
                time.sleep(waiting_till_next_login)
            signIn()
        else:
            print("Congrats! You are signed in !")
            user = User.objects(username=user.username).modify(set__failed_logins_counter=0)
            
            # Generate random port number for a connected user
            port = randint(1025, 9999)
            # User is connected and therfore cable of entering the chatroom
            register_in_key_server(user.username, port)
            
            return user.username, port
            

# =============================================================================
# def signOut() :
#     global user
#     # Delete the user's session ?! or global variable lenna ?!
#     user = None
#     
#     # Remove user from the key server
# =============================================================================
    

        
# =============================================================================
# def send_auth_email(recipient_email_address, secret_code):
#     import smtplib
#     FROM = 'yosra.dridi270@gmail.com'    
#     TO = [recipient_email_address]     
#     SUBJECT = "Authentication Secret Code"    
#     TEXT = str(secret_code)
#     
#     # Prepare actual message
#     message = """\
#     From: %s
#     To: %s
#     Subject: %s
#     
#     %s
#     """ % (FROM, ", ".join(TO), SUBJECT, TEXT)
#     
#     # Send the mail    
#     server = smtplib.SMTP('localhost')
#     server.sendmail(FROM, TO, message)
#     server.quit()
# =============================================================================