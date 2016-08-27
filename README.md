# apisecurity

[![Build Status](https://travis-ci.org/delatbabel/apisecurity.png?branch=master)](https://travis-ci.org/delatbabel/apisecurity)
[![StyleCI](https://styleci.io/repos/50161241/shield)](https://styleci.io/repos/50161241)
[![Latest Stable Version](https://poser.pugx.org/delatbabel/apisecurity/version.png)](https://packagist.org/packages/ddpro/apisecurity)
[![Total Downloads](https://poser.pugx.org/delatbabel/apisecurity/d/total.png)](https://packagist.org/packages/delatbabel/apisecurity)

API Security Helpers is designed for security of API connections, typically REST or
other HTTP based APIs, where the authentication process typically involves a shared
secret key, perhaps a public/private key pair, rather than username/password/cookie
type security more commonly found in web applications.

## Recent Changes

### v1.0

First stable release.

### v1.1

Added caching and verification of nonces (server and client side).

### v1.2

Added a new Key generator class to generate and store shared keys.  The existing Key
class (which handled public/private key pairs) has been renamed to KeyPair -- so if
you were using that class directly then use it as KeyPair instead of Key.

## Features

* Building cryptographic nonces
* Building public/private key pairs
* Signing API requests
* Verifying the signature of API requests

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

### Signature Calculation (Client)

Signatures use an RSA key pair.  To generate the signature requires knowledge of the private
key from the key pair.

```php
$client = new Client();
// $private_key_data can be the file name of the private key or the text of the key itself.
// This should be known only to the client.
$client->setPrivateKey($private_key_data);
$client->createSignature($request_data);
```

A client nonce will be generated and stored as `$request_data['cnonce']`.  A signature will
be generated and stored as `$request_data['sig']`.

### HMAC Calculation (Client)

HMACs use a shared key.

```php
$client = new Client();
// $shared_key_data can be the file name of the shared key or the text of the key itself.
// This should be known to both the client and server.
$client->setSharedKey($shared_key_data);
$client->createHMAC($request_data);
```

A client nonce will be generated and stored as `$request_data['cnonce']`.  An HMAC will
be generated and stored as `$request_data['hmac']`.

### Signature Verification (Server)

Verification of the signature requires knowledge of the client's public key.

```php
$server = new Server();
// $public_key can be the file name of the client's public key or the text of the key itself.
$server->setPublicKey($public_key);
$server->verifySignature($request_data);
```

A SignatureException is thrown if the signature is not valid.

### HMAC Verification (Server)

Verification of the HMAC requires knowledget of the shared key.

```php
$server = new Server();
// $shared_key can be the file name of the key or the text of the key itself.
$server->setSharedKey($shared_key);
$server->verifyHMAC($request_data);
```

A SignatureException is thrown if the HMAC is not valid.

### Server Nonce Generation (Server)

This step is optional, and ties a particular request to a client's IP address.  It requires
an extra API call as follows:

```
    Client                           Server
      |                                |
      |   Request server nonce         |
      | --------------------------->   |
      |                                |
      |   Server nonce provided        |
      | <---------------------------   |
      |                                |
      |                                |
      |   API call including snonce    |
      | --------------------------->   |
      |                                |
      |                         Verify |
      |                                |
      |   API response                 |
      | <---------------------------   |
      |                                |
```

On the server side, server nonce creation or verification can be achieved using any class that
implements \Delatbabel\ApiSecurity\Interfaces\CacheInterface.  There are two reference classes
provided within the \Delatbabel\ApiSecurity\Implementations namespace:

* LaravelCache -- uses the Laravel Cache facade for add/get.
* MemcachedCache -- uses the PHP native Memcached class to provide add/get.

To perform nonce verification, initialise the Server class with an object that implements
the CacheInterface interface, for example:

```php
$server = new Server(null, new MemcachedCache());
```

To create the nonce, this is the correct call:

```php
$server->createNonce($ip_address);
```

`$ip_address` is the client's IP address, e.g. from the $_SERVER array or similar.

### Nonce Verification (Server)

On the server side, nonce verification requires a server object initialised with a cache
object as per Nonce creation, above, for example:

```php
$server = new Server(null, new MemcachedCache());
```

Nonce verification rules are as follows:

* A client nonce must be present and must never have been used.
* A server nonce may be present. If it is present it must have been created on the server for the
  specific IP address of the client.

A NonceException is thrown if either the client nonce or the server nonce are not valid.

Nonce verification happens automatically during the `verifySignature` or `verifyHMAC` calls.

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
