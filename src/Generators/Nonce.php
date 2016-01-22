<?php
/**
 * Class Nonce
 *
 * @author del
 */

namespace Delatbabel\ApiSecurity\Generators;

/**
 * Class Nonce
 *
 * This class generates client or server side nonces.
 *
 * ### Example
 *
 * <code>
 * // Generate a nonce
 * $nonce = new Nonce();
 * echo "Nonce is " . $nonce->getNonce() . "\n";
 * </code>
 *
 * @link https://en.wikipedia.org/wiki/Cryptographic_nonce
 */
class Nonce
{
    /** @var int binary nonce length. This will be smaller than the base64 encoded version */
    protected $length;

    /** @var string 8 bit representation of nonce */
    protected $bytes;

    /** @var string base64 encoded (7 bit) representation of nonce */
    protected $nonce;

    public function __construct($length=16)
    {
        $this->setLength($length);
        $this->generate();
    }

    /**
     * Set the length of nonces to be generated.
     *
     * @param int $length
     * @return Nonce provides a fluent interface.
     */
    public function setLength($length=16)
    {
        $this->length = $length;
        return $this;
    }

    /**
     * Return the length of nonces that will be generated.
     *
     * @return int
     */
    public function getLength()
    {
        return $this->length;
    }

    /**
     * Create the nonce.
     *
     * @return Nonce provides a fluent interface
     */
    public function generate()
    {
        $usable = true;
        $this->bytes = openssl_random_pseudo_bytes($this->length, $usable);
        if ($usable === false) {
            // echo "Nonce is weak\n";
        }

        $this->nonce = base64_encode($this->bytes);
        return $this;
    }

    /**
     * Return the string (base64) representation of the nonce.
     *
     * @return string
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * Return the binary representation of the nonce.
     *
     * @return string
     */
    public function getBytes()
    {
        return $this->bytes;
    }
}
