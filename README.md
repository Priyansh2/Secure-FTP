# Secure-FTP
Designed and built a basic TCP-oriented Secure File Transfer Protocol (SFTP) with Diffie-Hellmann key exchange protocol, modified Caesar Cipher for encryption, DSS signature scheme, and SHA1 for password hashing.

# Requirements
* Python3

# Usage

```
Run server :- python server.py 
Run client :- python client.py    
```

# Project Scope
* Multiple client support with threading 
* Command-line interface with options: ``signup``, ``login``, ``chat``, ``download``
* Implemented authentic, secure file transfer system with Diffie-Hellmann key exchange protocol, modified Caesar Cipher and Digital Signature Algorithm
* Implemented password hashing using SHA-1 secure hash function 
* Implemented Miller-Rabin primality test and prime factorization algorithms like Pollard rho and Quadratic sieve    

# TODO
* MD5 checksum to handle file transfer errors.
* Directory ``Download`` 
* ``Upload`` feature to upload any kind of file and folders
* Data compression and archiving 
* Experiment with other better encryption standards
