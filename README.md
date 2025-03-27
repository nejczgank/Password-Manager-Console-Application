# Password Manager
Simple console based password manager that is able to: view entries, add entries, delete entries and set a master password.

## How does it work
It produces two documents: entries.txt and masterpassword.txt. The latter stores the passwords and encrypts them using sha256, whereas the former stores the hash of the master password used to access the application. The encryption/decryption key is generated from the masterpassword thus preventing anyone to simply edit the hash contained within masterpassword.txt and obtaining access to your private informaton.

## Dependencies
OpenSSL##

Add this application to path for easy access
