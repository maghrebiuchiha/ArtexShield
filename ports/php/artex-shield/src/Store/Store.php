<?php
declare(strict_types=1);

namespace ArtexShield\Store;

/**
 * Where scores and blocks live between requests. Values are plain arrays and
 * scalars. lock()/unlock() are advisory and per key: they serialise the
 * read-modify-write of one client's track, and of the block table, across
 * concurrent PHP workers.
 */
interface Store
{
    public function get(string $key): mixed;

    public function set(string $key, mixed $value, int $ttl): void;

    public function delete(string $key): void;

    public function lock(string $key): void;

    public function unlock(string $key): void;
}
