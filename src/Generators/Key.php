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
        /** @var resource $private_key */
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
     * Load the keys from files or strings.
     *
     * It's not required to provide both the private and the public
     * key. The key will be initialised with whichever or both keys
     * are provided.
     *
     * @param string $public_key file name or contents
     * @param string $private_key file name or contents
     */
    public function load($public_key='', $private_key='')
    {
        // If the private key is a file name then convert it to
        // the contents of the file (which should be an RSA private
        // key in PEM format)
        if (file_exists($private_key)) {
            $this->private_key_text = file_get_contents($private_key);
        } elseif (! empty($private_key)) {
            $this->private_key_text = $private_key;
        }

        // If the public key is a file name then convert it to
        // the contents of the file (which should be an RSA public
        // key in PEM format)
        if (file_exists($public_key)) {
            $this->public_key_text = file_get_contents($public_key);
        } elseif (! empty($public_key)) {
            $this->public_key_text = $public_key;
        }
    }

    /**
     * Sign some string and return the base64 encoded signature.
     *
     * Returns null if there was a problem signing the data (key not valid, etc)
     *
     * @param string $data_to_sign
     * @return null|string
     */
    public function sign($data_to_sign)
    {
        // Get the private key resource from the private key data
        $private_key = openssl_pkey_get_private($this->private_key_text);
        if ($private_key === false) {
            return null;
        }

        // Create the base64 encoded copy of the signature.
        $signature = '';
        if (! openssl_sign($data_to_sign, $signature, $private_key, OPENSSL_ALGO_SHA256)) {
            return null;
        }
        $base64_signature = base64_encode($signature);

        return $base64_signature;
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
