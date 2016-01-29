<?php
/**
 * Class LaravelCache.
 *
 * @author del
 */
namespace Delatbabel\ApiSecurity\Implementations;

use Delatbabel\ApiSecurity\Interfaces\CacheInterface;
use Illuminate\Support\Facades\Cache;

/**
 * Class LaravelCache.
 *
 * Implementation of CacheInterface that will work with Laravel applications.
 */
class LaravelCache implements CacheInterface
{
    public function add($key, $value)
    {
        Cache::put($key, $value, 60);
    }

    public function get($key)
    {
        return Cache::get($key);
    }
}
