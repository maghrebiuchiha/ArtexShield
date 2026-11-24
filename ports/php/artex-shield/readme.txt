=== ARTEX Shield ===
Tags: security, firewall, bot, scanner, honeypot
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 1.0.0
License: MIT

Detects and blocks ARTEX-style automated penetration testing before WordPress handles the request.

== Description ==

ARTEX is a self-hosted, AI-driven penetration-testing platform. This plugin scores each visitor's address from what it does on your site. It looks at scanner User-Agents, probes for files that should not exist, attack payloads in URLs, guessing of paths, machine-paced requests, and decoys nobody should touch. It throttles (429) and then blocks (403) the ones that add up.

* **Monitor mode by default.** It logs what it would stop and stops nothing until you switch to enforce.
* **Decoys, planted for you:** canary paths in robots.txt and the page, and optional fake credentials (honeytokens) that block whoever presents them.
* **An optional client-side check** that notices driven browsers, as soft evidence only. Visitors without JavaScript are never affected.
* **Requests a page made a visitor's browser send** are never held against the visitor.
* **Blocks expire,** and repeat offences double the time.
* **State lives where it lasts:** in the object cache when it is persistent, otherwise in files.

It is a port of the open-source artex-shield Python package and is held to the same test cases.

== Installation ==

1. Upload the `artex-shield` folder to `wp-content/plugins/`, or the zip under Plugins → Add New.
2. Activate it. It makes a random secret, plants the decoys and starts in monitor mode.
3. Behind a load balancer, proxy or CDN, list its address ranges under Settings → ARTEX Shield → Trusted proxies. Otherwise every visitor looks like the proxy.
4. Watch "Recent events" on the same page for a week. When it shows no visitor you would have stopped, choose Enforce.

== Frequently Asked Questions ==

= Someone was blocked by mistake =

They see a reference in the 403 page. Find it under Recent events or in the PHP error log, then press Unblock next to their network under "Blocked now".

= Does it read request bodies? =

Only with honeytokens on, and only the first 64 KiB, to look for the planted credentials. Attack payloads in bodies are not scored.

== Changelog ==

= 1.0.0 =
* First release.
