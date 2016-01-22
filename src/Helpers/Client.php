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
 * Example
 *
 * <code>
 *   // Example code goes here
 * </code>
 *
 * @see  ...
 * @link ...
 */
class Client
{
    /**
     * Construct a signature for a request signature, or return null if there is none.
     *
     * Adds the following array entities to $request_data:
     *
     * * cnonce -- the client generated nonce
     * * sig -- the signature, signed with the private key in $key
     *
     * Returns the sigature, or null if there was no signature.
     *
     * @param string $request_url
     * @param array $request_data
     * @param Key $key
     * @return string|null
     */
    protected function createSignature($request_url, array &$request_data, Key $key)
    {
        // Make a nonce
        $nonce = new Nonce();
        $request_data['cnonce'] = $nonce->getNonce();

        // Get the data to be signed.
        $query_string = http_build_query($request_data);
        $data_to_sign = $request_url . '?' . $query_string;

        // Create the base64 encoded copy of the signature.
        $base64_signature = $key->sign($data_to_sign);
        if (! empty($base64_signature)) {
            $request_data['sig'] = $base64_signature;
        }

        return $base64_signature;
    }
}
