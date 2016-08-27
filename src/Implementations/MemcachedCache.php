<?php
/**
 * Class MemcachedCache.
 *
 * @author del
 */
namespace Delatbabel\ApiSecurity\Implementations;

use Delatbabel\ApiSecurity\Interfaces\CacheInterface;

/**
 * Class MemcachedCache.
 *
 * Implementation of CacheInterface that will work with the native Memcached
 * interface in PHP.
 */
class MemcachedCache implements CacheInterface
{
    /** @var \Memcached The memcached instance */
    protected $memcached;

    /** @var  int Cache expiry time */
    protected $expiry_time;

    /**
     * Constructor.
     *
     * @param int    $expiry_time The cache expiry time in minutes.
     * @param string $server      name or IP address of the memcached server
     * @param int    $port        the port number of the memcached server.
     */
    public function __construct($expiry_time = 60, $server = 'localhost', $port = 11211)
    {
        $this->memcached = new \Memcached();
        $servers         = [
            [$server, $port],
        ];
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
