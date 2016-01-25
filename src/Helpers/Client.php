<?php
/**
 * Class Client
 *
 * @author del
 */

namespace Delatbabel\ApiSecurity\Helpers;

use Delatbabel\ApiSecurity\Generators\Key;
use Delatbabel\ApiSecurity\Generators\Nonce;


/**
 * Class Client
 *
 * Helper functions for API clients
 *
 * ### Example
 *
 * <code>
 * // Get the data to be signed.
 * $request_url = $this->getEndpoint();
 *
 * // Sign the data
 * $client = new Client();
 * $client->setPrivateKey($private_key_data);
 * $client->createSignature($request_data);
 * </code>
 *
 * @see Server
 */
class Client
{
    /** @var  Key -- must contain at least the client side private key for creating signatures */
    protected $key;

    /** @var  Nonce client side nonce */
    protected $cnonce;

    /** @var  string -- shared client/server key used in HMAC calculations */
    protected $sharedKey;

    /**
     * Client constructor.
     *
     * @param Key|null $key
     */
    public function __construct(Key $key=null)
    {
        if (empty($key)) {
            $this->key = new Key();
        } else {
            $this->key = $key;
        }
    }

    /**
     * Set the private key text
     *
     * @param string $key
     * @return Client provides a fluent interface.
     */
    public function setPrivateKey($key)
    {
        $this->key->setPrivateKey($key);
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
     * Generate a one time only client nonce.
     *
     * @return string
     */
    public function createNonce()
    {
        // Make a nonce
        $this->cnonce = new Nonce();
        return $this->cnonce->getNonce();
    }

    /**
     * Construct a request signature, or return null if there is none.
     *
     * Creating a signature requires knowledge of the client's private key.  The client
     * can send the signature to the server without the server having knowledge of the
     * client's private key.  The server only needs to know the public key that relates
     * to the private key.  See the Key class for generating public/private key pairs.
     *
     * A client generated nonce is also created and added to the request data.  This
     * *should* (but does not have to be) checked and verified on the server.  The nonce
     * is used to ensure that no two requests have the same data even if the endpoint
     * and request data are the same.
     *
     * The request data *should* (but does not have to) contain a server generated nonce.
     * The server generated nonce should be used exactly once -- generated on the server,
     * used by the client and then discarded.
     *
     * Adds the following array entities to $request_data:
     *
     * * cnonce -- the client generated nonce
     * * sig -- the signature, signed with the private made by setPrivateKey
     *
     * Returns the signature, or null if there was no signature.
     *
     * @param array $request_data
     * @return string|null
     */
    public function createSignature(array &$request_data)
    {
        // Make a nonce
        $request_data['cnonce'] = $this->createNonce();

        // Get the data to be signed.
        $data_to_sign = http_build_query($request_data);

        // Create the base64 encoded copy of the signature.
        $base64_signature = $this->key->sign($data_to_sign);
        if (! empty($base64_signature)) {
            $request_data['sig'] = $base64_signature;
        }

        return $base64_signature;
    }

    /**
     * Construct a HMAC for a request.
     *
     * Creating a HMAC for a request requires knowledge of a key that is shared between
     * the client and server and should not be disclosed to any third party.
     *
     * A client generated nonce is also created and added to the request data.  This
     * *should* (but does not have to be) checked and verified on the server.  The nonce
     * is used to ensure that no two requests have the same data even if the endpoint
     * and request data are the same.
     *
     * The request data *should* (but does not have to) contain a server generated nonce.
     * The server generated nonce should be used exactly once -- generated on the server,
     * used by the client and then discarded.
     *
     * Adds the following array entities to $request_data:
     *
     * * cnonce -- the client generated nonce
     * * hmac -- the hmac, created with the shared key made by setSharedKey()
     *
     * Returns the HMAC
     *
     * @param array $request_data
     * @return string
     */
    public function createHMAC(array &$request_data)
    {
        // Make a nonce
        $request_data['cnonce'] = $this->createNonce();

        // Get the data to be signed.
        $data_to_sign = http_build_query($request_data);

        // Create the base64 encoded copy of the HMAC.
        $base64_hmac = base64_encode(hash_hmac("sha256", $data_to_sign, $this->sharedKey, true));
        $request_data['hmac'] = $base64_hmac;

        return $base64_hmac;
    }
}
