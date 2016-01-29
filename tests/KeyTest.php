<?php
/**
 * Class KeyTest.
 *
 * @author del
 */
use Delatbabel\ApiSecurity\Generators\Key;

/**
 * Class KeyTest.
 *
 * Test case for Key class.
 */
class KeyTest extends PHPUnit_Framework_TestCase
{
    public function testCreateKey()
    {
        $key = new Key();
        $this->assertTrue($key instanceof Key);
        $this->assertEquals(32, $key->getLength());
    }

    public function testGenerate()
    {
        $key = new Key();
        $key->generate();
        $sharedKey = $key->getSharedKey();
        $this->assertEquals(32, strlen($sharedKey));
    }

    public function testGenerateAndSign()
    {
        $key = new Key();
        $key->generate();

        $data_to_sign = 'The quick brown fox jumps over the lazy dog';
        $signature = $key->sign($data_to_sign);

        $this->assertTrue($key->verify($data_to_sign, $signature));
    }

    public function testLoadAndFail()
    {
        $key = new Key();
        $key->generate();

        $data_to_sign = "On the whole, I'd rather be in Philadelphia";
        $signature = 'This is not the correct signature';

        $this->assertFalse($key->verify($data_to_sign, $signature));
    }
}
