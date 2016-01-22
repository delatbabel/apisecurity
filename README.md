# apisecurity

API Security Helpers is designed for security of API connections, typically REST or
other HTTP based APIs, where the authentication process typically involves a shared
secret key, perhaps a public/private key pair, rather than username/password/cookie
type security more commonly found in web applications.

Under Construction

## Installing

```
composer require delatbabel/apisecurity
```

## Example Use Cases

* Building cryptographic nonces
* Building public/private key pairs
* Signing API requests
* Verifying the signature of API requests

## Appropriate Frameworks

* Laravel
* Yii
* Zend Framework
* Symfony

This requires a relatively recent version of PHP with the openssl library compiled in
or loaded as a module.
