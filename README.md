# wopenssl
OpenSSL wrapper classes.
This components allows to manage digital certificates through PHP OpenSSL extension. It also offers basic
encrypt/decrypt of data as well as signature and validation of signature.

##Install
Add the key



to the composer require.

##Usage
###Class Certificate
This class allows to create certificates and to get information from them. When creating an instance, it is required
to pass the path to a valid openssl.cnf file.
When creating a certificate, the public key is attached to the certificate. The private key is stored in a pem file.
###Class Signature
Encapsulates signature and signature verification procedures.
###Class Crypt
Offers encrypt and decrypt data. Encryption needs a certificate public key and decryption needs the corresponding
certificate private key.

##Testing instructions
Change to tests directory and execute

```phpunit```

without arguments.
phpunit.xml is used to define default settings.

##License
This software is licensed under the GNU GPL v3 license.
