<?php
/**
 * The request PHP is handling, read the way the Python adapters and the
 * proxy read theirs: header values as Latin-1 bytes, the path percent-decoded
 * as UTF-8, the query as sent.
 */
declare(strict_types=1);

namespace ArtexShield;

final class Request
{
    public function __construct(
        public readonly string $peer,
        public readonly string $method,
        public readonly string $path,
        public readonly string $query,
        public readonly array $headers,       // lower-case name => value, in arrival order
        public readonly bool $https,
    ) {
    }

    public static function fromGlobals(array $server): self
    {
        $headers = [];
        $raw = function_exists('getallheaders') ? (getallheaders() ?: []) : [];
        if (!$raw) {
            foreach ($server as $k => $v) {
                if (str_starts_with((string) $k, 'HTTP_')) {
                    $raw[str_replace('_', '-', substr((string) $k, 5))] = $v;
                }
            }
            foreach (['CONTENT_TYPE' => 'Content-Type', 'CONTENT_LENGTH' => 'Content-Length'] as $k => $name) {
                if (isset($server[$k]) && $server[$k] !== '') {
                    $raw[$name] = $server[$k];
                }
            }
        }
        foreach ($raw as $name => $value) {
            $lower = Py::lower((string) $name);
            $value = Py::latin1((string) $value);
            $headers[$lower] = isset($headers[$lower]) ? $headers[$lower] . ($lower === 'cookie' ? '; ' : ', ') . $value : $value;
        }
        $target = (string) ($server['REQUEST_URI'] ?? '/');
        if (preg_match('~^https?://[^/?#]*~i', $target, $m)) {
            $target = substr($target, strlen($m[0]));
            $target = str_starts_with($target, '/') ? $target : '/' . $target;
        }
        $target = explode('#', $target, 2)[0];
        $q = strpos($target, '?');
        $rawPath = $q === false ? $target : substr($target, 0, $q);
        $query = $q === false ? '' : substr($target, $q + 1);
        $https = (!empty($server['HTTPS']) && strtolower((string) $server['HTTPS']) !== 'off')
            || (string) ($server['SERVER_PORT'] ?? '') === '443';
        return new self(
            (string) ($server['REMOTE_ADDR'] ?? ''),
            strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET')),
            Py::unquote(Py::latin1($rawPath)),
            Py::latin1($query),
            $headers,
            $https,
        );
    }

    public function hasBody(): bool
    {
        $length = trim($this->headers['content-length'] ?? '');
        return ($length !== '' && $length !== '0') || isset($this->headers['transfer-encoding']);
    }

    /**
     * The first $limit bytes of the body, for the honeytoken check. PHP keeps
     * php://input readable afterwards, so WordPress still gets the whole body.
     * A multipart form is not in php://input (PHP has parsed it into $_POST),
     * so its fields are given instead, form-encoded.
     */
    public function body(int $limit, array $post): string
    {
        $body = (string) @file_get_contents('php://input', false, null, 0, $limit);
        if ($body === '' && $post) {
            $body = substr(http_build_query($post), 0, $limit);
        }
        return $body;
    }
}
