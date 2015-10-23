#!/usr/bin/python2
# coding: utf-8
import json
import base64
import os
from cryptography.fernet import Fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import github3

def git_connect(github_username, github_password, github_repo):
    """
Logs in to github with our creds, returns gh,repo,branch objects.
    """
    return gh,repo,branch


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
    return our_salt,gh,repo,branch

def retrieve_config(master_password):
    """
Reads in the config file stored in ~/.gitpass.conf, decrypts the github password, and returns the our_salt,gh,repo,branch objects for use.
    """
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
    return encrypted_data

def decrypt(master_password, our_salt, data):
    """
Decrypts data with our salt and master password for extreme levels of security!!!
    """
    return decrypted_data

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

# holy fuck, am I seriously building this?
