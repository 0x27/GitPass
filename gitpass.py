#!/usr/bin/python2
# coding: utf-8
import json
import base64
import binascii
import os
from cryptography.fernet import Fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import github3
import getpass
import datetime

def git_connect(github_username, github_password, github_repo):
    """
Logs in to github with our creds, returns gh,repo,branch objects.
    """
    gh = github3.login(username=github_username, password=github_password) # we login and get a session.
    repo = gh.repository(github_username,github_repo) # we create our repo object
    branch = repo.branch("master") # hardcode this right fucking now
    return gh,repo,branch # return our objects...

def first_run_config(master_password):
    """
First run configuration: accepts our master password, creates a salt, asks for and tests github creds/repo. Saves the following to ~/.gitpass.conf
{
    'salt': our_salt,
    'github_username': github_username,
    'github_password': github_password_encrypted,
    'github_repo': github_repo
}
It returns the our_salt,gh,repo,branch objects. branch is set to master, just fucking because why the hell not.
    """
    print "{+} Generating salt..."
    our_salt = os.urandom(16) # salty
    try:
        github_username = raw_input("Please input your github username: ").strip()
    except Exception, e:
        return False,False,False
    try:
        github_password = getpass.getpass("Please input your github password: ").strip() # we will change this to getpass.
    except Exception, e:
        return False,False,False
    try:
        github_repo = raw_input("Please input your github repository: ").strip()
    except Exception, e:
        return False,False,False
    config_data = {'salt': our_salt.encode('base64'),
                'github_username': github_username,
                'github_password': encrypt(master_password=master_password, our_salt=our_salt, data=github_password),
                'github_repo': github_repo}
    config_file = os.getenv("HOME")+"/.gitpass.conf"
    with open(config_file, "w") as outfile:
        json.dump(config_data, outfile)
    print "{+} Configuration file written!"
    print "{*} Logging into Github now..."
    gh,repo,branch = git_connect(github_username=github_username, github_password=github_password, github_repo=github_repo)
    return our_salt,gh,repo,branch

def retrieve_config(master_password):
    """
Reads in the config file stored in ~/.gitpass.conf, decrypts the github password, and returns the our_salt,gh,repo,branch objects for use.
    """
    config_file = os.getenv("HOME")+"/.gitpass.conf"
    configuration = json.loads(open(config_file, "rb").read())
    our_salt = configuration['salt'].decode('base64')
    github_username = configuration['github_username']
    github_password = decrypt(master_password=master_password, our_salt=our_salt, data=configuration['github_password'])
    github_repo = configuration['github_repo']
    gh,repo,branch = git_connect(github_username=github_username, github_password=github_password, github_repo=github_repo)
    return our_salt,gh,repo,branch

def git_push(gh, repo, branch, data):
    """
Pushes our data to the github repo. Stores it in a file named "gitpass", obviously. Returns True if success, or False if failure.
    """
    return True

def git_pull(gh, repo, branch):
    """
Pulls our data from the github repo. Only looks for files named "gitpass" in "master". Returns data if success, or fails and some other fucking shit handles the error.
    """
    return data

def encrypt(master_password, our_salt, data):
    """
Encrypts data with our salt and master password for extreme levels of security!!!
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=our_salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))
    f = Fernet(key)
    encrypted_data = f.encrypt(b"%s"%(data))
    return encrypted_data # its encoded in some way already.

def decrypt(master_password, our_salt, data):
    """
Decrypts data with our salt and master password for extreme levels of security!!!
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=our_salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password))
    f = Fernet(key)
    data_enc = binascii.unhexlify(data.encode('hex')) # filthy hack
    decrypted_data = f.decrypt(data_enc)
    return decrypted_data

# keystore handler shit
"""
# this is the 'raw', unencrypted, keystore. Passwords are decrypted on access:
{
    "creds":[
             {
             "site": "https://www.facebook.com",
             "username": "nevergonnagive",
             "password": "youup",
             "datetime": "2015-10-23 21:58:22.375668"
             },
             {
             "site": "https://www.twitter.com",
             "username": "nevergonnalet",
             "password": "youdown",
             "datetime": "2015-10-23 21:58:22.375668"
             },
             {
             "site": "https://www.reddit.com",
             "username": "nevergonnarun",
             "password": "around",
             "datetime": "2015-10-23 21:58:22.375668"
             },
             {
             "site": "https://www.myspace.com",
             "username": "anddesert",
             "password": "you",
             "datetime": "2015-10-23 21:58:22.375668"
             }
            ]
}
# the 'password' values are encrypted before writing to git.
# datetime.datetime.now() is used to get the date of storing/updating.
"""

def insert_password(master_password, our_salt, username, password, webshite, password_store): 
    """
Inserts a set of credentials into the password store.
    """
    return password_store

def retrieve_password(master_password, our_salt, index, password_store):
    """
Retrieves a password from the password store. Passwords are indexed with a numbering system.
    """
    return password

def update_password(master_password, our_salt, index, password_store, password):
    """
Updates a password record in the data store (by adding a new record to it and sorting it, so we have history!)
    """
    return password_store

def delete_password(master_password, our_salt, index, password_store):
    """
Deletes a record from our password store (LOL, NOT REALLY, ITS STORED ON GITHUB ANYWAY)
    """
    return password_store

def list_passwords(password_store):
    """
Simply reads in the password store, and lists them off like the following.
[0] user: rick@astley.com site: https://facebook.com
[1] user: rick@astley.com site: https://twitter.com
...
Basically, makes it easy to list your usernames.
    """
    return True

def print_help():
    """
Sometimes users need help.
    """

def spawn_interactive_prompt(master_password, our_salt, gh, repo, branch):
    """
This is the interactive "shell".
    """
    print "Welcome to the GitPass Console. Type 'help' for help."
    while True:
        try:
            command = raw_input("GitPass> ")
        except KeyboardInterrupt:
            sys.exit("{!} Caught Ctrl+C, lets bail!")
        if command == "help":
            print_help()
        if command == "list":
            list_passwords(password_store=password_store)
        if command == "pull":
            password_store = git_pull(gh, repo, branch)
        if command == "commit":
            git_push(gh, repo, branch, data=password_store)

def main():
    if os.path.exists(os.getenv("HOME")+"/.gitpass.conf") != True:
        master_password = getpass.getpass("Please enter a master password. You will need to remember this! > ").strip()
        if getpass.getpass("Please re-enter your master password to verify > ").strip() != master_password:
            sys.exit("Eh. Try again.")
        else:
            our_salt,gh,repo,branch = first_run_config(master_password=master_password)
    else:
        master_password = getpass.getpass("Password: ").strip()
        our_salt,gh,repo,branch = retrieve_config(master_password=master_password)
    spawn_interactive_prompt(master_password=master_password, our_salt=our_salt, gh=gh, repo=repo, branch=branch)

if __name__ == "__main__":
    main()

# holy fuck, am I seriously building this?
