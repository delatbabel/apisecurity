<?php
/**
 * Class NonceTest.
 *
 * @author del
 */
use Delatbabel\ApiSecurity\Generators\Nonce;

/**
 * Class NonceTest.
 *
 * Test case for Nonce class.
 */
class NonceTest extends PHPUnit_Framework_TestCase
{
    public function testCreateNonce()
    {
        $nonce = new Nonce();
        $this->assertEquals(16, $nonce->getLength());
        $nonce_text = $nonce->getNonce();
        $nonce_bytes = $nonce->getBytes();
        $this->assertEquals(16, strlen($nonce_bytes));
        $this->assertEquals(24, strlen($nonce_text));
    }
}
