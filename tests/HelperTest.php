<?php
/**
 * Class HelperTest
 *
 * @author del
 */

use Delatbabel\ApiSecurity\Generators\Key;
use Delatbabel\ApiSecurity\Helpers\Client;
use Delatbabel\ApiSecurity\Helpers\Server;

/**
 * Class HelperTest
 *
 * Test case for Helper classes.
 */
class HelperTest extends PHPUnit_Framework_TestCase
{
    protected $pubkey;
    protected $privkey;
    protected $sharedkey;

    public function setUp()
    {
        $this->pubkey = __DIR__ . '/data/public.pem';
        $this->privkey = __DIR__ . '/data/private.pem';
        $this->sharedkey = 'i9DEgKMbGayMEAusiYswcex1LHfEsodb';
    }

    public function testCreateClient()
    {
        $client = new Client();
        $this->assertTrue($client instanceof Client);
    }

    public function testCreateClientNonce()
    {
        $client = new Client();
        $cnonce = $client->createNonce();
        $this->assertEquals(24, strlen($cnonce));
    }

    public function testCreateServerNonce()
    {
        $server = new Server();
        $snonce = $server->createNonce();
        $this->assertEquals(24, strlen($snonce));
    }

    public function testSignAndVerify()
    {
        $key = new Key();
        $key->generate();
        $key->store($this->pubkey, $this->privkey);
        $this->assertTrue(file_exists($this->pubkey));
        $this->assertTrue(file_exists($this->privkey));

        $client = new Client();
        $client->setPrivateKey($this->privkey);
        $data = [
            'fox'       => 'quick',
            'colour'    => 'brown',
            'dog'       => 'lazy',
        ];

        $signature = $client->createSignature($data);
        $this->assertNotEmpty($signature);

        $this->assertTrue(is_string($data['cnonce']));
        $this->assertTrue(is_string($data['sig']));

        $server = new Server();
        $server->setPublicKey($this->pubkey);

        $server->verifySignature($data);
    }

    public function testHmacAndVerify()
    {
        $client = new Client();
        $client->setSharedKey($this->sharedkey);
        $data = [
            'fox'       => 'quick',
            'colour'    => 'brown',
            'dog'       => 'lazy',
        ];

        $signature = $client->createHMAC($data);
        $this->assertNotEmpty($signature);

        $this->assertTrue(is_string($data['cnonce']));
        $this->assertTrue(is_string($data['hmac']));

        $server = new Server();
        $server->setSharedKey($this->sharedkey);

        $server->verifyHMAC($data);
    }

}
