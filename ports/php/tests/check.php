<?php
/** A very small test harness: no PHPUnit, nothing to install. */
declare(strict_types=1);

final class Failure extends \Exception
{
}

$GLOBALS['__checks'] = ['pass' => 0, 'fail' => 0];

/** Run one named check; a Failure or any other throwable fails it. */
function check(string $name, callable $fn): void
{
    $t0 = microtime(true);
    try {
        $fn();
        $GLOBALS['__checks']['pass']++;
        printf("ok    %s (%.0f ms)\n", $name, (microtime(true) - $t0) * 1000);
    } catch (\Throwable $e) {
        $GLOBALS['__checks']['fail']++;
        printf("FAIL  %s\n      %s\n", $name, str_replace("\n", "\n      ", $e instanceof Failure ? $e->getMessage()
            : get_class($e) . ': ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine()));
    }
}

function same(mixed $want, mixed $got, string $what = ''): void
{
    if ($want !== $got) {
        throw new Failure(($what !== '' ? "$what\n" : '') . 'expected ' . var_export($want, true) . "\n     got " . var_export($got, true));
    }
}

function truthy(mixed $got, string $what = ''): void
{
    if (!$got) {
        throw new Failure("expected true: $what");
    }
}

function throws(callable $fn, string $what = ''): void
{
    try {
        $fn();
    } catch (\InvalidArgumentException $e) {
        return;
    }
    throw new Failure("expected it to be refused: $what");
}

/** Print the totals; the exit status for the script. */
function report(): int
{
    $c = $GLOBALS['__checks'];
    printf("%d passed, %d failed\n", $c['pass'], $c['fail']);
    return $c['fail'] ? 1 : 0;
}
