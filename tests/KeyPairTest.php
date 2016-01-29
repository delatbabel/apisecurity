<?php
/**
 * Class KeyPairTest.
 *
 * @author del
 */
use Delatbabel\ApiSecurity\Generators\KeyPair;

/**
 * Class KeyPairTest.
 *
 * Test case for KeyPair class.
 */
class KeyPairTest extends PHPUnit_Framework_TestCase
{
    protected $pubkey;
    protected $privkey;

    public function setUp()
    {
        $this->pubkey = __DIR__.'/data/public.pem';
        $this->privkey = __DIR__.'/data/private.pem';
    }

    public function testCreateKey()
    {
        $key = new KeyPair();
        $this->assertTrue($key instanceof KeyPair);
        $this->assertEquals(OPENSSL_KEYTYPE_RSA, $key->getType());
    }

    public function testGenerateAndStore()
    {
        $key = new KeyPair();
        $key->generate();
        $key->store($this->pubkey, $this->privkey);
        $this->assertTrue(file_exists($this->pubkey));
        $this->assertTrue(file_exists($this->privkey));
    }

    public function testGenerateAndSign()
    {
        $key = new KeyPair();
        $key->generate();

        $data_to_sign = 'The quick brown fox jumps over the lazy dog';
        $signature = $key->sign($data_to_sign);

        $this->assertTrue($key->verify($data_to_sign, $signature));
    }

    public function testLoadAndSignWithFiles()
    {
        $key = new KeyPair();
        $key->load($this->pubkey, $this->privkey);

        $data_to_sign = 'Now is the time for all good men to come to the aid of the party';
        $signature = $key->sign($data_to_sign);

        $this->assertTrue($key->verify($data_to_sign, $signature));
    }

    public function testLoadAndSignWithText()
    {
        $public_contents = file_get_contents($this->pubkey);
        $private_contents = file_get_contents($this->privkey);

        $key = new KeyPair();
        $key->load($public_contents, $private_contents);

        $data_to_sign = 'The quick brown fox jumps over the lazy dog';
        $signature = $key->sign($data_to_sign);

        $this->assertTrue($key->verify($data_to_sign, $signature));
    }

    public function testLoadAndFail()
    {
        $key = new KeyPair();
        $key->load($this->pubkey, $this->privkey);

        $data_to_sign = "On the whole, I'd rather be in Philadelphia";
        $signature = 'This is not the correct signature';

        $this->assertFalse($key->verify($data_to_sign, $signature));
    }

    public function testGettersAndSetters()
    {
        $public_contents = file_get_contents($this->pubkey);
        $private_contents = file_get_contents($this->privkey);

        $key = new KeyPair();
        $key->setPublicKey($public_contents);
        $this->assertEquals($public_contents, $key->getPublicKey());

        $key->setPrivateKey($private_contents);
        $this->assertEquals($private_contents, $key->getPrivateKey());
    }
}
