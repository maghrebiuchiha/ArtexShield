<?php
declare(strict_types=1);

namespace ArtexShield;

/**
 * One client's state. PHP forgets everything between requests, so a track
 * is saved to the store after each request and read back on the next; to
 * keep that small, it holds only what can still change a decision.
 */
final class Track
{
    public float $hard = 0.0;              // points from signals that repeat on every hit
    public float $softPoints = 0.0;        // once-per-half-life points, capped at soft_cap
    public float $updated;
    public array $times = [];              // request times, for flood and cadence
    public array $notFound = [];           // when each newly missing path was first asked for
    public array $slow = [];               // the same, for the hourly allowance
    public array $missing = [];            // missing path -> when last asked for (128 kept)
    public array $soft = [];               // soft label -> when it last counted
    public int $strikes = 0;
    public float $throttledUntil = 0.0;
    public ?float $pageAt = null;          // first HTML page served (client check)
    public ?float $checkedAt = null;       // last completed client check
    public ?float $automationAt = null;    // last check that reported automation

    public function __construct(float $now)
    {
        $this->updated = $now;
    }

    public function score(): float
    {
        return $this->hard + $this->softPoints;
    }

    /** Append with a length limit, dropping the oldest: deque(maxlen=$max).append. */
    public static function push(array &$ring, float $x, int $max): void
    {
        $ring[] = $x;
        if (count($ring) > $max) {
            array_shift($ring);
        }
    }

    public function toArray(float $now, float $rateWindow, int $cadenceSamples): array
    {
        // Request times older than the rate window and outside the last
        // cadence_samples can change no decision, so they are not kept.
        $times = $this->times;
        $keep = count($times) - $cadenceSamples;
        for ($i = 0; $i < $keep && $now - $times[$i] > $rateWindow; $i++) {
        }
        return ['h' => $this->hard, 's' => $this->softPoints, 'u' => $this->updated, 't' => array_slice($times, $i),
            'n' => $this->notFound, 'w' => $this->slow, 'm' => $this->missing, 'f' => $this->soft, 'k' => $this->strikes,
            'r' => $this->throttledUntil, 'p' => $this->pageAt, 'c' => $this->checkedAt, 'a' => $this->automationAt];
    }

    public static function fromArray(array $a): self
    {
        $t = new self((float) $a['u']);
        $t->hard = (float) $a['h'];
        $t->softPoints = (float) $a['s'];
        $t->times = array_map('floatval', $a['t']);
        $t->notFound = array_map('floatval', $a['n']);
        $t->slow = array_map('floatval', $a['w']);
        $t->missing = array_map('floatval', $a['m']);
        $t->soft = array_map('floatval', $a['f']);
        $t->strikes = (int) $a['k'];
        $t->throttledUntil = (float) $a['r'];
        $t->pageAt = $a['p'] === null ? null : (float) $a['p'];
        $t->checkedAt = $a['c'] === null ? null : (float) $a['c'];
        $t->automationAt = $a['a'] === null ? null : (float) $a['a'];
        return $t;
    }
}
