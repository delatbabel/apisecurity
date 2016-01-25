# apisecurity

API Security Helpers is designed for security of API connections, typically REST or
other HTTP based APIs, where the authentication process typically involves a shared
secret key, perhaps a public/private key pair, rather than username/password/cookie
type security more commonly found in web applications.

I am getting close to an 1.0 release -- more functionality is to be added but the
interface should be reasonably stable now.

## Features

* Building cryptographic nonces
* Building public/private key pairs
* Signing API requests
* Verifying the signature of API requests

## TODO

* Nonce verification, using a cache store

## Installing

```
composer require delatbabel/apisecurity
```

Once that is done, run the composer update command:

```
composer update
```

## Examples

### Simple client or server side nonce generation

```php
// Generate a nonce
$nonce = new Nonce();
echo "Nonce is " . $nonce->getNonce() . "\n";
```

### Signature Calculation

```php
$client = new Client();
// $private_key_data can be the file name of the private key or the text of the key itself.
// This should be known only to the client.
$client->setPrivateKey($private_key_data);
$client->createSignature($request_data);
```

### Signature Verification

```php
$server = new Server();
// $public_key can be the file name of the client's public key or the text of the key itself.
$server->setPublicKey($public_key);
$server->verifySignature($request_data);
```

Take a look at the class docblocks and the test cases for more examples of use.

## Appropriate Frameworks

* Laravel
* Yii
* Zend Framework
* Symfony

This requires a relatively recent version of PHP with the openssl library compiled in
or loaded as a module.

# Architecture

I do not provide all of the possible options for API security functions.  For example,
I don't provide the ability to generate DSA or DH keys (not yet supported by the PHP
openssl extensions), and the default keys are 2048 bit RSA keys (1024 bit keys are broken).
I don't provide all possible signature hash algorithms -- SHA256 is the one to use.

Another example is that a client nonce is added to each request automatically before
the signature is created -- this prevents two requests that otherwise have the same data
from having the same signature (and hence leading to denial of service attacks).  You
can choose not to verify the client nonce if you so choose but it will always be there.

This is in an attempt to provide best-practice rather than fully flexible security.

The rationale for this is that I have seen too many APIs with limited or poor security.
e.g. having a username / password pair and passing those as part of the API data in
plain text is **not** a valid security solution.

Some attention has to be paid to what is practical vs what is most secure.  It would be
ideal to public key encrypt every API request, however the added time required to do that
would start to be significant.  Another option would be to seal (shared key encrypt, and
pass the shared key in a public key encrypted packet), however this would still have the
disadvantage that it would defeat HTTP handling libraries in various frameworks that expect
to be able to parse the HTTP POST data before handing off the data elsewhere.

Of course it's still possible to encrypt or seal particularly sensitive data within the
POST body, but that's maybe an exercise for a later version.
