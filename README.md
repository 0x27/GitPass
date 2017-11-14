# GitPass - Open Source Your Password (Mismanagement)!

## What?
GitPass is an Open Source Password Mismanager, using [Military Strength][charlatan] [Fernet][Fernet] Cryptography and [High Availability Cloud Hosting Services][bullshit] 

## Features
* [MILITARY STRENGTH][charlatan] [Fernet][Fernet] Cryptography!
* Password history, thanks to the wonderful powers of Git!
* Command Line Interface! 
* [High Availabilty Cloud Hosting Service][bullshit] for Password Storage!
* Notifies you when you should change your passwords! (Coming Soon!)
* Free and Open Source Software!
* Written in Python! Batteries are DEFINITELY included!
* Unnecessary Amounts of Hyperbole!

## How does it work?
You will need exactly two things for this to work.

1. A Github Account
2. Passwords to store

You run the program. On first run, you make a Master Password, and add credentials for your Github Account, along with the name of the repository you want to store your passwords in. The credentials are put in a JSON file and encrypted for future use using the Master Password, along with the repository name.

You then can start adding passwords to the program. These are stored in an encrypted JSON container (using your Master Password), and put into The Cloud by the Git Magicks into the Github Repository.

To retrieve passwords, you can "list", "retrieve", "add", "update", and "delete". You simply select the account you want to Mismanage, and manage away! It even notifies you on initialization if one of your passwords has not been changed in a while, and encourages you to update it!

It is advisable that you use a private repository for your keystore, however, it is mathematically improbable that, provided you choose good master password, the keystore can be cracked. Still, better safe than pwned!

## Requirements
* A computer with Python installed (only tested on GNU/Linux).
* Half a brain cell
* The following Python modules (which you can install via `pip install -r requirements.txt`
  * [cryptography][cryptography]  
  * [github3.py][github3] - note, for pip, this is named `github3.py`.

## Screenshots
### Initialization and help menu
![initandhelp](https://raw.githubusercontent.com/0x27/GitPass/master/screenshots/inithelp.png)

### Demo of List/Insert/Retrieve/Update functions
![demolistetc](https://raw.githubusercontent.com/0x27/GitPass/master/screenshots/listinsertretrieveupdate.png)

## Cryptography
This project uses the [Fernet][Fernet] encryption standard as implemented in the [cryptography.io][cryptography] library. [Fernet][Fernet] is a [symmetric encryption][symmetric encryption] algorithm using [AES][AES] in [CBC][CBC] mode with a 128 bit key for encryption, using [PKCS7][PKCS7] for padding. For more information about [Fernet][Fernet], consult the [Fernet Spec Document][FernetSpec]. We have avoided the use of home-rolled crypto here, and went with a believed-to-be-safe set of primitives using a supposedly-safe encryption library. Audits are much appreciated.

## Licence
[Licenced under the WTFPL (do Whatever The Fuck you want Public Licence)][Licence]

## Beer?
Send yer cryptologically generated beer tokens to fuel further opensource software:  
[coinbase, for convenience][coinbase], or the following bitcoin address: `13rZ67tmhi7M3nQ3w87uoNSHUUFmYx7f4V`

## Bug Reports and Feature Requests
Please submit all bug reports and feature requests to the [Github Issue Tracker][tracker]

## Footnote
Those who cannot recognise parody when they see it are doomed to a miserable existance.

[charlatan]: https://raw.githubusercontent.com/0x27/GitPass/master/img/charlatan.jpg
[bullshit]: https://raw.githubusercontent.com/0x27/GitPass/master/img/pure-bullshit.jpg
[Fernet]: https://github.com/fernet/spec/
[cryptography]: https://cryptography.io/en/latest/
[github3]: https://github3py.readthedocs.org/en/master/
[coinbase]: https://www.coinbase.com/infodox/
[Licence]: http://www.wtfpl.net/txt/copying/
[symmetric encryption]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm
[AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[CBC]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
[PKCS7]: https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
[FernetSpec]: https://github.com/fernet/spec/blob/master/Spec.md
[tracker]: https://github.com/0x27/GitPass/issues
