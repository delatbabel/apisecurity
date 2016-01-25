<?php
/**
 * Interface CacheInterface
 *
 * @author del
 */

namespace Delatbabel\ApiSecurity\Interfaces;

/**
 * Interface CacheInterface
 *
 * Defines the interface that applications need to provide to ApiSecurity for setting
 * and getting items from a cache.
 *
 * ### Example
 *
 * For examples on implementing this, see the sample implementations in ../Implementations
 */
interface CacheInterface
{
    /**
     * This function should add an item to the cache.
     *
     * The function is used for storing client and server side nonces.  The
     * length of time to store these nonces should be up to the implementation
     * but usually about 1 hour is sufficient.
     *
     * @param $key
     * @param $value
     * @return mixed
     */
    public function add($key, $value);

    /**
     * This function should retrieve an item from the cache.
     *
     * An empty value (e.g. null or false) should be returned if the item does
     * not exist in the cache.
     *
     * @param $key
     * @return mixed
     */
    public function get($key);
}
