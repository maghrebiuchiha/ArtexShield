<?php
declare(strict_types=1);

namespace ArtexShield;

/** What the shield decided about one request. */
final class Decision
{
    /**
     * @param string $action "pass" | "throttle" | "block" | "refuse"
     * @param bool $enforced false in monitor mode
     * @param string $ref incident reference shown to the client
     */
    public function __construct(
        public readonly string $action,
        public readonly bool $enforced,
        public readonly float $score,
        public readonly array $hits,
        public readonly string $ref,
        public readonly string $ip,
        public readonly int $retryAfter = 0,
        public readonly bool $friendly = false,
        public readonly bool $induced = false,
    ) {
    }

    /** True when the request must not reach the site. */
    public function stop(): bool
    {
        return $this->enforced && $this->action !== 'pass';
    }
}
