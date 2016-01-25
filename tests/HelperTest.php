<?php
/**
 * Class HelperTest
 *
 * @author del
 */

use Delatbabel\ApiSecurity\Generators\Key;
use Delatbabel\ApiSecurity\Helpers\Client;
use Delatbabel\ApiSecurity\Helpers\Server;
use Delatbabel\ApiSecurity\Implementations\MemcachedCache;
use Delatbabel\ApiSecurity\Exceptions\NonceException;
use Delatbabel\ApiSecurity\Exceptions\SignatureException;

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

    public function testVerifyServerNonce()
    {
        $cache = new MemcachedCache(60);
        $server = new Server(null, $cache);
        $snonce = $server->createNonce('1.1.1.1');
        $this->assertEquals(24, strlen($snonce));

        // Verify that it has been recorded for this IP address
        $server->verifyServerNonce($snonce, '1.1.1.1');
        $this->assertTrue(true);

        // Cannot verify a second time.
        try {
            $server->verifyServerNonce($snonce, '1.1.1.1');
            $this->assertTrue(false);
        } catch (NonceException $e) {
            $this->assertTrue(true);
        }

        // Cannot verify at the wrong IP address
        try {
            $server->verifyServerNonce($snonce, '2.2.2.2');
            $this->assertTrue(false);
        } catch (NonceException $e) {
            $this->assertTrue(true);
        }

        // Cannot verify a nonsense nonce
        try {
            $server->verifyServerNonce('Nonsense', '2.2.2.2');
            $this->assertTrue(false);
        } catch (NonceException $e) {
            $this->assertTrue(true);
        }
    }

    public function testVerifyClientNonce()
    {
        $cache = new MemcachedCache(60);
        $server = new Server(null, $cache);
        $client = new Client();
        $cnonce = $client->createNonce();
        $this->assertEquals(24, strlen($cnonce));

        // Verify that it is a virgin
        $server->verifyClientNonce($cnonce);
        $this->assertTrue(true);

        // Cannot verify a second time.
        try {
            $server->verifyClientNonce($cnonce);
            $this->assertTrue(false);
        } catch (NonceException $e) {
            $this->assertTrue(true);
        }
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
        $this->assertTrue(true);

        // Can't verify without signature
        unset($data['sig']);
        try {
            $server->verifySignature($data);
            $this->assertTrue(false);
        } catch (SignatureException $e) {
            $this->assertTrue(true);
        }

        // Can't verify garbage signature
        $data['sig'] = 'Garbage';
        try {
            $server->verifySignature($data);
            $this->assertTrue(false);
        } catch (SignatureException $e) {
            $this->assertTrue(true);
        }

        // Can't verify without cnonce
        $data = [
            'fox'       => 'quick',
            'colour'    => 'brown',
            'dog'       => 'lazy',
        ];

        $signature = $client->createSignature($data);
        $this->assertNotEmpty($signature);

        unset($data['cnonce']);
        try {
            $server->verifySignature($data);
            $this->assertTrue(false);
        } catch (SignatureException $e) {
            $this->assertTrue(true);
        }
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
        $this->assertTrue(true);

        // Can't verify without signature
        unset($data['hmac']);
        try {
            $server->verifyHMAC($data);
            $this->assertTrue(false);
        } catch (SignatureException $e) {
            $this->assertTrue(true);
        }

        // Can't verify garbage signature
        $data['hmac'] = 'Garbage';
        try {
            $server->verifyHMAC($data);
            $this->assertTrue(false);
        } catch (SignatureException $e) {
            $this->assertTrue(true);
        }

        // Can't verify without cnonce
        $data = [
            'fox'       => 'quick',
            'colour'    => 'brown',
            'dog'       => 'lazy',
        ];

        $signature = $client->createHMAC($data);
        $this->assertNotEmpty($signature);

        unset($data['cnonce']);
        try {
            $server->verifyHMAC($data);
            $this->assertTrue(false);
        } catch (SignatureException $e) {
            $this->assertTrue(true);
        }
    }
}
