# GitPass - Open Source Your Password (Mismanagement)!

## What?
GitPass is an Open Source Password Mismanager, using [Military Strength][charlatan] [Fernet][Fernet] Cryptography and [High Availability Cloud Hosting Services][bullshit] 

## Features
* [MILITARY STRENGTH][charlatan] [Fernet][Fernet] Cryptography!
* Password history!
* Command Line Interface!
* [High Availabilty Cloud Hosting Service][bullshit] for Password Storage!
* Notifies you when you should change your passwords!
* Free and Open Source Software!
* Written in Python!
* Unnecessary Amounts of Hyperbole!

## How does it work?
You will need exactly two things for this to work.

1. A Github Account
2. Passwords to store

You run the program. On first run, you make a Master Password, and add credentials for your Github Account, along with the name of the repository you want to store your passwords in. The credentials are put in a JSON file and encrypted for future use using the Master Password, along with the repository name.

You then can start adding passwords to the program. These are stored in an encrypted JSON container (using your Master Password), and put into The Cloud by the Git Magicks into the Github Repository.

To retrieve passwords, you can "list", "retrieve", "add", "update", and "delete". You simply select the account you want to Mismanage, and manage away! It even notifies you on initialization if one of your passwords has not been changed in a while, and encourages you to update it!

## Requirements
* A computer with Python installed (only tested on GNU/Linux).
* Half a brain cell
* The following Python modules (which you can install via `pip install -r requirements.txt`

[cryptography][cryptograhy-python]

## Licence
[Licenced under the WTFPL (do Whatever The Fuck you want Public Licence)][Licence]

## Beer?
Send yer cryptologically generated beer tokens to fuel further opensource software:  
[coinbase, for convenience][coinbase], or the following bitcoin address: `13rZ67tmhi7M3nQ3w87uoNSHUUFmYx7f4V`

[charlatan]: https://raw.githubusercontent.com/0x27/GitPass/master/img/charlatan.jpg
[bullshit]: https://raw.githubusercontent.com/0x27/GitPass/master/img/pure-bullshit.jpg
[Fernet]: https://github.com/fernet/spec/
[cryptography]: https://cryptography.io/en/latest/
[coinbase]: https://www.coinbase.com/infodox/
[Licence]: http://www.wtfpl.net/txt/copying/
