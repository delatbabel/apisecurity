<?php
/**
 * Class Server
 *
 * @author del
 */

namespace Delatbabel\ApiSecurity\Helpers;

use Delatbabel\ApiSecurity\Exceptions\NonceException;
use Delatbabel\ApiSecurity\Exceptions\SignatureException;
use Delatbabel\ApiSecurity\Generators\KeyPair;
use Delatbabel\ApiSecurity\Generators\Key;
use Delatbabel\ApiSecurity\Generators\Nonce;
use Delatbabel\ApiSecurity\Interfaces\CacheInterface;

/**
 * Class Server
 *
 * Long description of class goes here.  What is this for?
 *
 * ### Example
 *
 * <code>
 * // Verify the signature.  This will thrown an exception if there is
 * // no signature or if the signature did not verify.
 * $server = new Server();
 * $server->setPublicKey($public_key);
 * try {
 *     $server->verifySignature($request_data);
 * } catch (SignatureException $e) {
 *     // fail
 * }
 * </code>
 *
 * @see Client.
 */
class Server
{
    /** @var  KeyPair -- must contain at least the client side public key for verifying signatures */
    protected $keypair;

    /** @var  CacheInterface -- mechanism to store and retrieve from cache */
    protected $cache;

    /** @var  Nonce server side nonce */
    protected $snonce;

    /** @var  string -- shared client/server key used in HMAC calculations */
    protected $sharedKey;

    /**
     * Server constructor.
     *
     * @param KeyPair|null        $keypair
     * @param CacheInterface|null $cache
     */
    public function __construct(KeyPair $keypair=null, CacheInterface $cache=null)
    {
        if (empty($keypair)) {
            $this->keypair = new KeyPair();
        } else {
            $this->keypair = $keypair;
        }

        $this->cache = $cache;
    }

    /**
     * Set the public key text
     *
     * @param string $key
     * @return Server provides a fluent interface.
     */
    public function setPublicKey($key)
    {
        $this->keypair->setPublicKey($key);
        return $this;
    }

    /**
     * Set the shared key used in generating HMACs.
     *
     * @param $key
     * @return Client provides a fluent interface.
     */
    public function setSharedKey($key)
    {
        $this->sharedKey = $key;
        return $this;
    }

    /**
     * Generate a one time only server nonce.
     *
     * @param string $ip_address The client IP address where this nonce will be sent
     * @return string
     */
    public function createNonce($ip_address='127.0.0.1')
    {
        // Make a nonce
        $this->snonce = new Nonce();
        $snonce = $this->snonce->getNonce();
        $this->recordServerNonce($snonce, $ip_address);
        return $snonce;
    }

    /**
     * Verifies and stores a client nonce
     *
     * Throws a NonceException if the nonce does not verify (has been used).
     *
     * @param string $cnonce The client nonce key.
     * @throws NonceException
     */
    public function verifyClientNonce($cnonce)
    {
        $cnonce_cache_key = 'cnonce__' . $cnonce;

        if (empty($this->cache)) {
            return;
        }

        $cnonce_data = $this->cache->get($cnonce_cache_key);
        if ($cnonce_data == 'USED') {
            throw new NonceException('That nonce has already been used');
        }

        $this->cache->add($cnonce_cache_key, 'USED');
    }

    /**
     * Verifies a server nonce
     *
     * This ensures that the server nonce has been used once and once only,
     * and only by the same IP address that it was provided to.
     *
     * Throws a NonceException if the nonce does not verify (has been used
     * elsewhere or has never been used).
     *
     * @param string $snonce The server nonce key.
     * @param string $ip_address
     * @throws NonceException
     */
    public function verifyServerNonce($snonce, $ip_address='127.0.0.1')
    {
        $snonce_cache_key = 'snonce__' . $snonce;

        if (empty($this->cache)) {
            return;
        }

        $snonce_data = $this->cache->get($snonce_cache_key);
        if (empty($snonce_data)) {
            throw new NonceException('That nonce has been not been generated');
        }
        if ($snonce_data !== $ip_address) {
            throw new NonceException('That nonce has been used elsewhere');
        }

        $this->cache->add($snonce_cache_key, 'USED');
    }

    /**
     * Records a server nonce
     *
     * This records a server nonce after creation.
     *
     * @param string $snonce The server nonce key.
     * @param string $ip_address
     */
    public function recordServerNonce($snonce, $ip_address='127.0.0.1')
    {
        $snonce_cache_key = 'snonce__' . $snonce;

        if (empty($this->cache)) {
            return;
        }

        $this->cache->add($snonce_cache_key, $ip_address);
    }

    /**
     * Verify a signature on the request URL, the request data and the key.
     *
     * Verifying the signature requires knowledge of the client's public key, which
     * can be made public knowledge.  It does not require knowledge of the client's
     * private key, which should be known only to the client.  Each client should have
     * a unique public/private key pair.  See the KeyPair class for generating public/
     * private key pairs.
     *
     * The request data *should* contain a nonce generated on the client and it
     * *should* contain a nonce generated on the server.  The client nonce should
     * never have been used before (generated and used once, then discarded), and
     * the server nonce should have been used exactly once before (generated by
     * the server, used once and then discarded).  These nonces ensure that the
     * request data is unique even for identical requests.
     *
     * An exception is thrown if the signature did not verify or was not present.
     *
     * @param array  $request_data
     * @param string $ip_address
     * @return void
     * @throws SignatureException
     * @throws NonceException
     */
    public function verifySignature(array $request_data, $ip_address='127.0.0.1')
    {
        if (empty($request_data['sig'])) {
            throw new SignatureException('No signature was present on the request data');
        }

        $base64_signature = $request_data['sig'];

        // Get the data that needs to be verified.
        unset($request_data['sig']);
        $data_to_verify = http_build_query($request_data);

        // Verify the signature
        $verify = $this->keypair->verify($data_to_verify, $base64_signature);
        if (! $verify) {
            throw new SignatureException('The signature on the request data did not verify');
        }

        // Verify the client nonce if present.  This will normally be created at
        // the time that the signature is created.
        if (empty($request_data['cnonce'])) {
            throw new NonceException('No client nonce was present in signature verification');
        }
        $this->verifyClientNonce($request_data['cnonce']);

        // Verify the server nonce if present.  Note that the client must request
        // this.
        if (! empty($request_data['snonce'])) {
            $this->verifyServerNonce($request_data['snonce'], $ip_address);
        }
    }

    /**
     * Verify a HMAC for a request.
     *
     * Verifying a HMAC for a request requires knowledge of a key that is shared between
     * the client and server and should not be disclosed to any third party.
     *
     * The request data *should* contain a nonce generated on the client and it
     * *should* contain a nonce generated on the server.  The client nonce should
     * never have been used before (generated and used once, then discarded), and
     * the server nonce should have been used exactly once before (generated by
     * the server, used once and then discarded).  These nonces ensure that the
     * request data is unique even for identical requests.
     *
     * An exception is thrown if the signature did not verify or was not present.
     *
     * @param array $request_data
     * @param string $ip_address
     * @return void
     * @throws SignatureException
     * @throws NonceException
     */
    public function verifyHMAC(array $request_data, $ip_address='127.0.0.1')
    {
        if (empty($request_data['hmac'])) {
            throw new SignatureException('No HMAC was present on the request data');
        }

        // Get the data that needs to be verified.
        $supplied_hmac = $request_data['hmac'];
        unset($request_data['hmac']);
        $data_to_verify = http_build_query($request_data);

        // Verify the client nonce if present.  This will normally be created at
        // the time that the HMAC is created.
        if (empty($request_data['cnonce'])) {
            throw new NonceException('No client nonce was present in signature verification');
        }
        $this->verifyClientNonce($request_data['cnonce']);

        // Create the shared key object
        $sharedKey = new Key();
        $sharedKey->setSharedKey($this->sharedKey);

        // Verify the signature.
        $verify = $sharedKey->verify($data_to_verify, $supplied_hmac);

        if (! $verify) {
            throw new SignatureException('The HMAC on the request data did not verify');
        }

        // Verify the server nonce if present.  Note that the client must request
        // this.
        if (! empty($request_data['snonce'])) {
            $this->verifyServerNonce($request_data['snonce'], $ip_address);
        }
    }
}
