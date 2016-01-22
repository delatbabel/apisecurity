<?php
/**
 * Class Key
 *
 * @author del
 */

namespace Delatbabel\ApiSecurity\Generators;


/**
 * Class Key
 *
 * Handles the generation of public / private key pairs.
 *
 * ### Example
 *
 * <code>
 * $keypair = new Key();
 * $public_key = $keypair->getPublicKey();
 * $private_key = $keypair->getPrivateKey();
 * </code>
 *
 * @link http://php.net/manual/en/ref.openssl.php
 * @link https://www.openssl.org/docs/
 */
class Key
{
    /** @var int key length. Ideally this should be 2048, 1024 bit RSA keys are broken */
    protected $length;

    /** @var  string key type, at the moment only OPENSSL_KEYTYPE_RSA is supported */
    protected $type;

    /** @var  string text of the private key */
    protected $private_key_text;

    /** @var  string text of the public key */
    protected $public_key_text;

    /**
     * Key constructor.
     *
     * @param int $length
     * @param int $type
     */
    public function __construct($length=2048, $type=OPENSSL_KEYTYPE_RSA)
    {
        $this->setLength($length);
        $this->setType($type);
        $this->generate();
    }

    /**
     * Set the length of keys to be generated.
     *
     * @param int $length
     * @return Key provides a fluent interface.
     */
    public function setLength($length=2048)
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
     * Set the type of keys to be generated.
     *
     * @param int $type
     * @return Key provides a fluent interface.
     */
    public function setType($type=OPENSSL_KEYTYPE_RSA)
    {
        $this->type = $type;
        return $this;
    }

    /**
     * Return the type of keys that will be generated.
     *
     * @return int
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * Create the key pair.
     *
     * @return Key provides a fluent interface
     */
    public function generate()
    {
        // Make a new key pair
        $private_key = openssl_pkey_new([
            'private_key_bits'      => 2048,
            'private_key_type'      => OPENSSL_KEYTYPE_RSA,
            'encrypt_key'           => false,
        ]);

        // Export the key pair to a string
        $this->private_key_text = '';
        openssl_pkey_export($private_key, $this->private_key_text);

        // Get the public key
        $public_key_data = openssl_pkey_get_details($private_key);
        $this->public_key_text = $public_key_data['key'];
    }

    /**
     * Store the keys into files.
     *
     * @param string $public_key_file
     * @param string $private_key_file
     */
    public function store($public_key_file, $private_key_file)
    {
        file_put_contents($public_key_file, $this->public_key_text);
        file_put_contents($private_key_file, $this->private_key_text);
        chmod($private_key_file, 0600);
    }

    /**
     * Get the public key text
     *
     * @return string
     */
    public function getPublicKey()
    {
        return $this->public_key_text;
    }

    /**
     * Get the private key text
     *
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->private_key_text;
    }
}
