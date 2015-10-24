#!/usr/bin/python2
# coding: utf-8
import json
import ast
import base64
import binascii
import os
import sys
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
    except Exception, e: # here we have an exception. We should handle or log it.
        return False,False,False # something else can bitch about this if it fucks up, I guess. XXX: Add error handling.
    try:
        github_password = getpass.getpass("Please input your github password: ").strip() 
    except Exception, e: # here we have an exception. We should handle or log it.
        return False,False,False # something else can bitch about this if it fucks up, I guess. XXX: Add error handling.
    try:
        github_repo = raw_input("Please input your github repository: ").strip()
    except Exception, e: # here we have an exception. We should handle or log it.
        return False,False,False # something else can bitch about this if it fucks up, I guess. XXX: Add error handling.
    config_data = {'salt': our_salt.encode('base64'),
                'github_username': github_username,
                'github_password': encrypt(master_password=master_password, our_salt=our_salt, data=github_password),
                'github_repo': github_repo}
    config_file = os.getenv("HOME")+"/.gitpass.conf" # I have no idea if this works on Windows. Works on Linux just fine.
    with open(config_file, "w") as outfile:
        json.dump(config_data, outfile) # theres gotta be a nicer way of doing this
    print "{+} Configuration file written!"
    print "{*} Logging into Github now..." # this whole section here needs error/exception handling and shit.
    gh,repo,branch = git_connect(github_username=github_username, github_password=github_password, github_repo=github_repo)
    print "{*} Creating blank password store..."
    commit = repo.create_file("gitpass","initiate",base64.b64encode('{"creds":[]}'))# hack, to get around some stupid fucking errors
    return our_salt,gh,repo,branch # these are useful objects

def retrieve_config(master_password):
    """
Reads in the config file stored in ~/.gitpass.conf, decrypts the github password, and returns the our_salt,gh,repo,branch objects for use.
    """
    config_file = os.getenv("HOME")+"/.gitpass.conf" # works on linux, fucked if I know about windows
    configuration = json.loads(open(config_file, "rb").read()) # this works fine, but is sub optimal.
    our_salt = configuration['salt'].decode('base64') # yeah, we had to encode the salt...
    github_username = configuration['github_username'] # should we encrypt this for the craic? maybe
    github_password = decrypt(master_password=master_password, our_salt=our_salt, data=configuration['github_password']) # death to plaintext
    github_repo = configuration['github_repo'] # we might encrypt this too, for shits and giggles
    gh,repo,branch = git_connect(github_username=github_username, github_password=github_password, github_repo=github_repo) # this needs exception handling
    return our_salt,gh,repo,branch

def git_push(gh, repo, branch, data):
    """
Pushes our data to the github repo. Stores it in a file named "gitpass", obviously. Returns True if success, or False if failure.
    """
    try:
        commit = repo.contents(path="gitpass").update(message="lol", content=base64.b64encode(str(data))) # fucking bodge
    except Exception, e:
        print e # we didn't handle it, we just print it and fucking move on. We should handle it.
        print "{!!} Oh no! Something wen't wrong! Try again later!"

def git_pull(gh, repo, branch):
    """
Pulls our data from the github repo. Only looks for files named "gitpass" in "master". Returns data if success, or fails and some other fucking shit handles the error.
    """
    data = base64.b64decode(base64.b64decode(repo.contents(path="gitpass").content)) # kludge for another bug
    return data.strip() # bloody sneaky newlines

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
    encrypted_site = encrypt(master_password=master_password, our_salt=our_salt, data=webshite)
    encrypted_username = encrypt(master_password=master_password, our_salt=our_salt, data=username)
    encrypted_password = encrypt(master_password=master_password, our_salt=our_salt, data=password)
    new_record = {"site": encrypted_site, "username": encrypted_username, "password": encrypted_password, "datetime": '%s'%(datetime.datetime.now())}
    password_store['creds'].append(new_record)
    print "{*} Inserted!"
    return password_store

def retrieve_password(master_password, our_salt, index, password_store):
    """
Retrieves a password from the password store. Passwords are indexed with a numbering system.
    """
    credentials = password_store['creds'][int(index)]
    # we stick in our validity check here with the datetime... later.
    username = decrypt(master_password=master_password, our_salt=our_salt, data=credentials['username'])
    password = decrypt(master_password=master_password, our_salt=our_salt, data=credentials['password'])
    webshite = decrypt(master_password=master_password, our_salt=our_salt, data=credentials['site'])
    return username,password,webshite

def update_password(master_password, our_salt, index, password_store, password):
    """
Updates a password record in the data store (by adding a new record to it and sorting it, so we have history!)
    """
   
    credentials = password_store['creds'][int(index)]
    encrypted_password = encrypt(master_password=master_password, our_salt=our_salt, data=password)
    credentials['password'] = encrypted_password
    password_store['creds'].pop(int(index)) # we actually remove it and replace it
    password_store['creds'].append(credentials) # here we are popping it back on
    print "{*} Updated!"
    print "{!} You may want to run 'list' again buddy..."
    return password_store

def delete_password(master_password, our_salt, index, password_store):
    """
Deletes a record from our password store (LOL, NOT REALLY, ITS STORED ON GITHUB ANYWAY)
    """
    password_store['creds'].pop(int(index))
    print "{*} Deleted!"
    print "{!} You may want to run 'list' again buddy..."
    return password_store

def list_passwords(master_password, our_salt, password_store):
    """
Simply reads in the password store, and lists them off like the following.
[0] user: rick@astley.com site: https://facebook.com
[1] user: rick@astley.com site: https://twitter.com
...
Basically, makes it easy to list your usernames.

Later, we can add such nice things as "check the date and warn on 'expired' passwords!"
    """
    records = password_store['creds']
    for record in records:
        index = records.index(record)
        username_decrypted = decrypt(master_password=master_password, our_salt=our_salt, data=record['username'])
        webshite_decrypted = decrypt(master_password=master_password, our_salt=our_salt, data=record['site'])
        print "[%s] user: %s site: %s" %(index, username_decrypted, webshite_decrypted)
    return True

def print_help():
    """
Sometimes users need help.
    """
    print """\
GitPass Help Menu.
help - this help menu.
list - list passwords in the store.
insert - insert a password to the store.
retrieve - retrieve a password from the store.
update - update a password in the store.
delete - delete a password from the store.
pull - get the latest version of password store from git.
commit - commit changes to the store to the git.
quit/exit - quits. I should probably have added this earlier.
    """

def spawn_interactive_prompt(master_password, our_salt, gh, repo, branch):
    """
This is the interactive "shell".
    """
    print "Welcome to the GitPass Console. Type 'help' for help."
    password_store = ast.literal_eval(git_pull(gh, repo, branch)) # this is definately unsafe.
    while True:
        try:
            command = raw_input("GitPass> ")
        except KeyboardInterrupt:
            sys.exit("\n{!} Caught Ctrl+C, lets bail!")
        if command == "help":
            print_help()
        if command == "list":
            list_passwords(master_password=master_password, our_salt=our_salt, password_store=password_store)
        if command == "insert":
            # do insert, return password_store
            webshite = raw_input("Webshite: ").strip()
            username = raw_input("Your Username: ").strip()
            password = getpass.getpass("Your Password: ").strip()
            password_store = insert_password(master_password=master_password, our_salt=our_salt, username=username, password=password, webshite=webshite, password_store=password_store)
        if command == "retrieve":
            index = raw_input("Index of password you want to retrieve: ")
            username,password,webshite = retrieve_password(master_password=master_password, our_salt=our_salt, index=index, password_store=password_store)
            print "{>} Website: %s" %(webshite)
            print "{>} Username: %s" %(username)
            print "{>} Password: %s" %(password)
        if command == "update":
			# do update, return password store
            index = raw_input("Index number of password you wish to update: ").strip()
            password = getpass.getpass("New Password: ").strip()
            password_store = update_password(master_password=master_password, our_salt=our_salt, index=index, password_store=password_store, password=password)
        if command == "delete":
            # do delete, return password store
            index = raw_input("Index number of password you wish to delete: ").strip()
            password_store = delete_password(master_password=master_password, our_salt=our_salt, index=index, password_store=password_store)
        if command == "pull":
            password_store = ast.literal_eval(git_pull(gh, repo, branch)) # this is definately unsafe.
        if command == "commit":
            git_push(gh, repo, branch, data=password_store)
        if command == "quit" or "exit":
            sys.exit("Bye!")

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
# yes, yes you did. All because of a joke on irc.
