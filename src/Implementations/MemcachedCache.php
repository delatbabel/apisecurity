<?php
/**
 * Class MemcachedCache
 *
 * @author del
 */

namespace Delatbabel\ApiSecurity\Implementations;

use Delatbabel\ApiSecurity\Interfaces\CacheInterface;

/**
 * Class MemcachedCache
 *
 * Implementation of CacheInterface that will work with the native Memcached
 * interface in PHP.
 */
class MemcachedCache implements CacheInterface
{
    /** @var \Memcached The memcached instance */
    protected $memcached;

    /** @var  integer Cache expiry time */
    protected $expiry_time;

    /**
     * Constructor
     *
     * @param integer $expiry_time The cache expiry time in minutes.
     */
    public function __construct($expiry_time = 60, $server='localhost', $port=11211)
    {
        $this->memcached = new \Memcached();
        $servers = array(
            array($server, $port)
        );
        $this->memcached->addServers($servers);
        $this->expiry_time = $expiry_time;
    }

    public function add($key, $value)
    {
        $this->memcached->set($key, $value, $this->expiry_time * 60);
    }

    public function get($key)
    {
        $data = $this->memcached->get($key);
        // $result = $this->memcached->getResultCode();
        return $data;
    }
}
