<?php
declare(strict_types=1);

namespace ArtexShield\Store;

/**
 * State in the WordPress object cache. Only worth using with a persistent
 * backend (Redis, Memcached), which wp_using_ext_object_cache() reports;
 * WordPress's own cache lasts one request. Locks are a short-lived cache
 * entry taken with wp_cache_add, which is atomic in those backends.
 */
final class ObjectCacheStore implements Store
{
    private const GROUP = 'artex_shield';
    private array $held = [];

    public function get(string $key): mixed
    {
        $found = false;
        $value = wp_cache_get($key, self::GROUP, false, $found);
        return $found ? $value : null;
    }

    public function set(string $key, mixed $value, int $ttl): void
    {
        wp_cache_set($key, $value, self::GROUP, max(0, $ttl));
    }

    public function delete(string $key): void
    {
        wp_cache_delete($key, self::GROUP);
    }

    public function lock(string $key): void
    {
        for ($try = 0; $try < 40; $try++) {           // up to 0.2 s, then go ahead unlocked
            if (wp_cache_add("lock:$key", 1, self::GROUP, 5)) {
                $this->held[$key] = true;
                return;
            }
            usleep(5000);
        }
    }

    public function unlock(string $key): void
    {
        if (isset($this->held[$key])) {
            wp_cache_delete("lock:$key", self::GROUP);
            unset($this->held[$key]);
        }
    }
}
