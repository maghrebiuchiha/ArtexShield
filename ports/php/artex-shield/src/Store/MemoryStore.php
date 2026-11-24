<?php
declare(strict_types=1);

namespace ArtexShield\Store;

/**
 * State for one PHP process: tests, the vector runner, long-running servers.
 * Values are stored as JSON, as the persistent stores keep them, so what
 * passes here passes the round trip too.
 */
final class MemoryStore implements Store
{
    private array $data = [];

    public function get(string $key): mixed
    {
        return isset($this->data[$key]) ? json_decode($this->data[$key], true) : null;
    }

    public function set(string $key, mixed $value, int $ttl): void
    {
        $this->data[$key] = json_encode($value, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
    }

    public function delete(string $key): void
    {
        unset($this->data[$key]);
    }

    public function lock(string $key): void
    {
    }

    public function unlock(string $key): void
    {
    }
}
