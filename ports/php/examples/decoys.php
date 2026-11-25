<?php
/**
 * What to plant on a PHP site for the decoys examples/prepend.php watches
 * for, made from the same secret: as artex-shield-proxy --print-decoys does.
 *
 *   ARTEX_SHIELD_SECRET='...' php examples/decoys.php
 *   ARTEX_SHIELD_SECRET='...' ARTEX_SHIELD_CLIENT_CHECK=1 php examples/decoys.php
 */
declare(strict_types=1);

use ArtexShield\ClientCheck;
use ArtexShield\Decoys;

require __DIR__ . '/../artex-shield/autoload.php';

$secret = (string) (getenv('ARTEX_SHIELD_SECRET') ?: '');
if ($secret === '') {
    fwrite(STDERR, "Set ARTEX_SHIELD_SECRET to the secret examples/prepend.php uses.\n");
    exit(2);
}
$canaries = Decoys::canaries($secret);
$tokens = Decoys::honeytokens($secret);
echo "# robots.txt: add these lines\n", Decoys::robotsTxtBlock($canaries),
    "# HTML: a link no visitor sees, for your page template\n", Decoys::htmlTrap($canaries[0]), "\n\n",
    "# JavaScript: a dead constant, for your bundle\n", Decoys::jsTrap($canaries[count($canaries) - 1]), "\n\n",
    "# JavaScript: fake credentials, for your bundle\n", Decoys::honeytokenJs($tokens, 0), "\n\n",
    "# HTML: a comment with fake credentials, for your page template\n", Decoys::honeytokenHtml($tokens, 1), "\n";
if (in_array((string) getenv('ARTEX_SHIELD_CLIENT_CHECK'), ['1', 'true', 'yes', 'on'], true)) {
    echo "\n# HTML: the client check, on every page\n", ClientCheck::tag('/_artex/check'), "\n";
}
