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
 * <h4>Example</h4>
 *
 * <code>
 *   // Example code goes here
 * </code>
 *
 * @see  ...
 * @link ...
 */
class Server
{
    /**
     * Verify a signature on the request URL, the request data and the key.
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
