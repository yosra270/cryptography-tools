# cryptography-tools

* **Phase 1: Registration**

   In order to create an account users should enter the following informations :
   1. Email address (should be a **real** one)
   2. Username 
   3. Password (should follow **OWASP password strength recommendations** + should not be **pnwed**)

The entered informations will be validated as follows :

![sign up process](img/signup_process.png)

The data will be saved in a user table (Username, Email, pwd (hashed using **Argon2id**)) in a monogodb database.

* **Phase 2: Authentication**
  
  The authentication process is as follows :
  
  ![sign in process](img/signin_process.png)
  


* **Phase 3: Menu**

    1. Coding/decoding of a message
    2. Hash of a message/Cracking a hashed message (Md5, SHA1, SHA256, ...)
    3. Symmetric/Asymmetric encryption/decryption of a message (AES256, RSA, Elgamal, ..)
    4. Secure communication between two clients (ChatRoom) using **hybrid cryptosystem**

![secure communication process](img/chatroom_process.png)
