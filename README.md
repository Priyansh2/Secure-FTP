# Secure-FTP
Designed and built a basic TCP oriented Secure File Transfer Protocol (SFTP) with Diffie-Hellmann key exchange protocol, modified Caesar Cipher for encryption, DSS signature scheme and SHA1 for password hashing.

# Requirements
* Python3

# Usage

```
Run server :- python server.py 
Run client :- python client.py    
```

# Features
* Multiple client support with threading 
* Command line interface with options: ``signup``, ``login``, ``chat``, ``download``
* Implemented authentic, secure file transfer system with Diffie-Hellmann key exchange protocol, modified Caesar Cipher and Digital Signature Algorithm 
* Implemented Miller-Rabin primality test and prime factorization algorithms like Pollard rho and Quadratic sieve    

# TODO
* MD5 checksum to handle file transfer errors.
* ``Download`` feature for different file format (audio, video etc. ) including directories
* Data compression and archiving 
* ``Upload`` feature to upload any kind of file and folders
* Experiment with other better encryption standards
