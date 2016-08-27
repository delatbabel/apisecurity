<?php
/**
 * Class Key.
 *
 * @author del
 */
namespace Delatbabel\ApiSecurity\Generators;

if (! function_exists('hash_equals')) {
    function hash_equals($str1, $str2)
    {
        if (strlen($str1) != strlen($str2)) {
            return false;
        } else {
            $res = $str1 ^ $str2;
            $ret = 0;
            for ($i = strlen($res) - 1; $i >= 0; $i--) {
                $ret |= ord($res[$i]);
            }

            return ! $ret;
        }
    }
}

/**
 * Class Key.
 *
 * Handles the generation of symmetric keys.
 *
 * ### Example
 *
 * <code>
 * // Initialise
 * $key = new Key();
 *
 * // Generate a new symmetric key
 * $key->generate();
 *
 * // Fetch the binary version of the shared key
 * $key = $key->getSharedKey();
 * </code>
 *
 * @link http://php.net/manual/en/ref.openssl.php
 * @link https://www.openssl.org/docs/
 */
class Key
{
    /** @var int key length. Ideally this should be 32 (characters) */
    protected $length;

    /** @var  string binary representation of the shared key */
    protected $shared_key;

    /**
     * Key constructor.
     *
     * @param int $length
     */
    public function __construct($length = 32)
    {
        $this->setLength($length);
    }

    /**
     * Set the length of keys to be generated.
     *
     * @param int $length
     *
     * @return Key provides a fluent interface.
     */
    public function setLength($length = 32)
    {
        $this->length = $length;

        return $this;
    }

    /**
     * Return the length of keys that will be generated.
     *
     * @return int
     */
    public function getLength()
    {
        return $this->length;
    }

    /**
     * Set the shared key.
     *
     * @param string $key
     *
     * @return Key provides a fluent interface.
     */
    public function setSharedKey($key)
    {
        // If the public key is a file name then convert it to
        // the contents of the file (which should be an RSA public
        // key in PEM format)
        if (file_exists($key)) {
            $this->shared_key = file_get_contents($key);
        } elseif (! empty($key)) {
            $this->shared_key = $key;
        }

        return $this;
    }

    /**
     * Get the public key text.
     *
     * @return string
     */
    public function getSharedKey()
    {
        return $this->shared_key;
    }

    /**
     * Create the shared key.
     *
     * @return Key provides a fluent interface
     */
    public function generate()
    {
        // Make a new key
        $this->setSharedKey(openssl_random_pseudo_bytes($this->getLength()));

        return $this;
    }

    /**
     * Sign some string and return the base64 encoded signature.
     *
     * Returns null if there was a problem signing the data (key not valid, etc)
     *
     * @param string $data_to_sign
     *
     * @return string
     */
    public function sign($data_to_sign)
    {
        $base64_signature = base64_encode(hash_hmac('sha256', $data_to_sign, $this->getSharedKey(), true));

        return $base64_signature;
    }

    /**
     * Verify the signature of some data.
     *
     * @param string $data_to_verify
     * @param string $base64_signature
     *
     * @return bool
     */
    public function verify($data_to_verify, $base64_signature)
    {
        $calculated_signature = base64_encode(hash_hmac('sha256', $data_to_verify, $this->getSharedKey(), true));
        $verify               = hash_equals($calculated_signature, $base64_signature);

        return $verify;
    }
}
