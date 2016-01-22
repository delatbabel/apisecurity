<?php
/**
 * Class Server
 *
 * @author del
 */

namespace Delatbabel\ApiSecurity\Helpers;

use Delatbabel\ApiSecurity\Exceptions\SignatureException;
use Delatbabel\ApiSecurity\Generators\Key;


/**
 * Class Server
 *
 * Long description of class goes here.  What is this for?
 *
 * ### Example
 *
 * <code>
 * $key = new Key();
 * $key->load($public_key, '');
 *
 * // Verify the signature.  This will thrown an exception if there is
 * // no signature or if the signature did not verify.
 * $server = new Server();
 * try {
 *     $server->verifySignature($request_url, $request_data, $key);
 * } catch (SignatureException $e) {
 *     // fail
 * }
 * </code>
 *
 * ### TODO
 *
 * Function to create server side nonces.
 *
 * Function to verify HMACs.
 *
 * Function to validate nonces:
 *
 * * Server side nonce must have been used exactly once.
 * * Client side nonce must not have been used before.
 * * Nonces can be cached and cache can time out.
 *
 * @see Client.
 */
class Server
{
    /**
     * Verify a signature on the request URL, the request data and the key.
     *
     * An exception is thrown if the signature did not verify or was not present.
     *
     * @param string $request_url
     * @param array  $request_data
     * @param Key    $key
     * @return void
     * @throws SignatureException
     */
    public function verifySignature($request_url, array $request_data, Key $key)
    {
        if (empty($request_data['sig'])) {
            throw new SignatureException('No signature was present on the request data');
        }

        $base64_signature = $request_data['sig'];

        // Get the data that needs to be signed.
        unset($request_data['sig']);
        $query_string = http_build_query($request_data);
        $data_to_verify = $request_url . '?' . $query_string;

        // Verify the signature
        $verify = $key->verify($data_to_verify, $base64_signature);
        if (! $verify) {
            throw new SignatureException('The signature on the request data did not verify');
        }
    }
}
