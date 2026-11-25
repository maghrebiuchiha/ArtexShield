<?php
/**
 * The shield in front of the request PHP is handling, for any PHP site: the
 * WordPress plugin runs it as it loads, and examples/prepend.php runs it as
 * an auto_prepend_file before every script.
 *
 * It decides on the request, answers it here when it is stopped (403, or 429
 * with Retry-After) or is the client check's own, and otherwise lets PHP go
 * on, feeding the status and Content-Type it answered with back to the shield
 * when the script ends.
 */
declare(strict_types=1);

namespace ArtexShield;

final class Guard
{
    /** Decide on this request. Returns the decision when the request may go on; never returns otherwise. */
    public static function protect(Shield $shield, ?array $server = null, ?array $post = null): Decision
    {
        $request = Request::fromGlobals($server ?? $_SERVER);
        $ip = $shield->clientIp($request->peer, $request->headers['x-forwarded-for'] ?? null);
        $limit = $shield->cfg['honeytoken_body_limit'];
        $body = $shield->cfg['honeytokens'] && $limit && $request->hasBody() ? $request->body($limit, $post ?? $_POST) : null;
        $d = $shield->check($ip, $request->method, $request->path, $request->query, $request->headers, $body);
        if ($d->stop()) {
            self::answer(self::reply($d), $request->method);
        }
        $route = $shield->clientCheckRoute($request->path);
        if ($route !== null) {
            $proto = strtolower(trim(explode(',', $request->headers['x-forwarded-proto'] ?? '')[0]));
            $secure = $request->https || ($proto === 'https' && $shield->trustedPeer($request->peer));
            self::answer($route === 'script' ? $shield->clientCheckAsset()
                : $shield->clientCheckReply($ip, $request->query, $request->headers, $secure), $request->method);
        }
        register_shutdown_function(static function () use ($shield, $ip, $request, $d): void {
            $status = http_response_code();
            if (!is_int($status)) {
                return;
            }
            $type = '';
            foreach (headers_list() as $line) {
                if (stripos($line, 'content-type:') === 0) {
                    $type = trim(substr($line, 13));
                }
            }
            try {
                $shield->observe($ip, $request->path, $status, $d->induced, $type);
            } catch (\Throwable $e) {
                error_log('artex-shield: observe failed: ' . $e->getMessage());
            }
        });
        return $d;
    }

    /** What a stopped request gets: 403 or 429, plain text, a reference to quote. */
    public static function reply(Decision $d): array
    {
        if ($d->action === 'block' || $d->action === 'refuse') {
            $body = 'Request ' . ($d->action === 'block' ? 'blocked' : 'refused') . ". Reference: {$d->ref}\n";
            return ['status' => 403, 'headers' => [['Content-Type', 'text/plain; charset=utf-8'],
                ['Content-Length', (string) strlen($body)], ['Cache-Control', 'no-store']], 'body' => $body];
        }
        $body = "Too many requests. Reference: {$d->ref}\n";
        return ['status' => 429, 'headers' => [['Content-Type', 'text/plain; charset=utf-8'], ['Content-Length', (string) strlen($body)],
            ['Retry-After', (string) $d->retryAfter], ['Cache-Control', 'no-store']], 'body' => $body];
    }

    private static function answer(array $r, string $method): never
    {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
        http_response_code($r['status']);
        foreach ($r['headers'] as [$name, $value]) {
            header("$name: $value");
        }
        if ($method !== 'HEAD') {
            echo $r['body'];
        }
        exit;
    }
}
