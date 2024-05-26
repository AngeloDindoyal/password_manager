import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def create_salt():
    salt = os.urandom(16)
    with open('key.key', 'wb') as f:
        f.write(salt)

def load_key(pwd):
    file =  open('key.key', 'rb')
    salt = file.read()
    file.close()
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(pwd))
    return key


def view(fer):
    with open('password.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            user , pwd = data.split("|")
            print("User:",user,", Password:", fer.decrypt(pwd.encode()).decode())

def add(fer):
    name = input("Account name:\n")
    pwd = fer.encrypt(input("Password:\n").encode()).decode()

    with open('password.txt', 'a') as f:
        f.write(name + " | "  + pwd + "\n")


def main():
    key = None
    master_pwd = None
    
    while True: 
        own = input("Are you a new user? (y/n)\n").lower()
        if own == "y":
            master_pwd = input("What would you like the master password to be?\n")
            create_salt()
            key = load_key(master_pwd.encode())
            break
        elif own == "n":
            master_pwd = input("What is the master password?\n")
            key = load_key(master_pwd.encode())
            break
        else: 
            print("Invalid input")
            continue

    fer = Fernet(key)

    while True: 
        action = input("Would you like to (view/add) a pasword, or would you like to (quit) the program?\n").lower()
        if action == "quit":
            break
        elif action == "view":
            try:
                view(fer)
            except:
                print("You do not have any stored passwords or do not have access to these passwords.")
            continue
        elif action == "add":
            add(fer)
            continue
        else:
            print("Invalid input")
            continue
main()
