"""Radar signatures: what ARTEX and its bundled toolchain look like on the wire.

Every pattern here runs on text a client chose, on every request, so each one
must scan in time proportional to its input. Avoid shapes a backtracking
engine retries from every position: an unbounded run in front of a literal,
or two unbounded runs either side of one. tests/test_shield.py times every
pattern against hostile input.
"""
import re

# (pattern, points, label). 100 = block on sight.
# ARTEX's own identifiers, taken from its source:
#   config/task_user_agents.go        "ARTEX-Assessment/1.0 (engagement=REF)"  (handled by IFF)
#   skills/api-recon/scripts/*.py     "Mozilla/5.0 (spa-api-recon)" / "(spa-api-recon spider)"
#   server/update_check.go            "artex-update-check"
HARD_UA = [(re.compile(p, re.I), pts, label) for p, pts, label in [
    (r"spa-api-recon", 100, "artex:api-recon-harvester"),
    (r"artex-update-check", 100, "artex:update-check"),
    # Scanners shipped in the ARTEX image (Dockerfile), at their default UAs.
    (r"sqlmap", 100, "tool:sqlmap"),
    (r"fuzz faster u fool", 100, "tool:ffuf"),
    (r"nmap scripting engine", 100, "tool:nmap-nse"),
    (r"nuclei", 100, "tool:nuclei"),
    (r"dalfox", 100, "tool:dalfox"),
    (r"katana", 100, "tool:katana"),
    (r"projectdiscovery", 100, "tool:projectdiscovery"),
    # Common companions.
    (r"masscan|zgrab|nikto|wpscan|gobuster|feroxbuster|dirsearch|dirbuster|wfuzz|acunetix|nessus|openvas",
     100, "tool:scanner"),
]]
# Soft: scored once per decay period, never enough alone to throttle.
SOFT_UA = [(re.compile(p, re.I), pts, label) for p, pts, label in [
    (r"headlesschrome|phantomjs|puppeteer|playwright", 40, "ua:headless-browser"),
    (r"go-http-client|python-requests|python-urllib|python-httpx|aiohttp|^curl/|^wget/|libwww-perl|node-fetch|axios|undici",
     15, "ua:http-library"),
]]
ASSESSMENT_UA = re.compile(r"ARTEX-Assessment/\d+(?:\.\d+)*(?:\s*\(engagement=([A-Za-z0-9._-]{1,64})\))?", re.I)
# "Mozilla/5.0" and, somewhere after it, a browser token. Anchored on the first
# "Mozilla/5.0" so a User-Agent that repeats it is still read once.
BROWSER_UA = re.compile(r"\A(?:(?!mozilla/5\.0).)*mozilla/5\.0.*(?:chrome|firefox|safari|edg)/", re.I)
CRAWLER_UA = re.compile(r"bot|crawl|spider|slurp|preview|facebookexternalhit|monitor|uptime", re.I)

# Paths nobody requests by accident: scored on sight.
SENSITIVE_PATHS = re.compile(
    r"/\.(env|git|svn|hg|aws|ssh|DS_Store|htpasswd|htaccess|npmrc|dockerenv)(\b|/|$)"
    r"|/(id_rsa|id_dsa|wp-config\.php\.[a-z~]+|web\.config|phpinfo\.php|server-status|server-info)$",
    re.I)
# Dumps, backups and editor leftovers, told by name alone. A site can really
# serve handbook.zip or notes.old, so like the recon paths below these are
# scored only when YOUR app answers 404. "db" must not sit inside a longer
# word: mydb.sql and db_2026.zip, but not handbook.zip or feedback.zip.
MISSING_SENSITIVE = re.compile(
    r"/(?=[\w.-]*\.(?:sql|zip|tar|gz|bak|7z)$)[\w.-]*(?:backup|dump|database|(?<![a-z])db|db(?![a-z]))"
    r"|\.(bak|old|swp|orig)$",
    re.I)
# Recon paths: scored only when YOUR app answers 404, so real routes are safe.
RECON_PATHS = re.compile(
    r"^/(swagger(-ui)?(\.json|\.yaml|/.*)?|openapi\.(json|yaml)|(v[23]/)?api-docs.*|graphql|graphiql"
    r"|actuator(/.*)?|admin(/.*)?|console|debug(/.*)?|metrics|wp-login\.php|wp-admin(/.*)?|xmlrpc\.php"
    r"|phpmyadmin(/.*)?|manager/html|druid(/.*)?|nacos(/.*)?|jenkins(/.*)?|solr(/.*)?|\.well-known/security\.txt)$",
    re.I)
ODD_METHODS = {"TRACE", "TRACK", "CONNECT", "DEBUG"}
# Scanners use it, but so do Windows and Office whenever someone opens a link
# from a document (WebDAV discovery). Soft: once per half-life.
SOFT_METHODS = {"PROPFIND"}

PAYLOADS = [(re.compile(p, re.I), label) for p, label in [
    (r"union\s+(all\s+)?select|information_schema|\b(pg_)?sleep\s*\(\s*\d|benchmark\s*\(|waitfor\s+delay"
     r"|'\s*(or|and)\s+['\d]|xp_cmdshell|extractvalue\s*\(|updatexml\s*\(", "payload:sqli"),
    (r"<script|javascript:|on(error|load|mouseover|focus)\s*=|<svg[\s/]|<iframe", "payload:xss"),
    (r"\.\./\.\./|\.\.\\\.\.\\|/etc/(passwd|shadow)|win\.ini|/proc/self/", "payload:traversal"),
    # Shell separators also join ordinary lists (`fields=name|id|price`, `color=red;id=5`),
    # so a short word after a single separator counts only with an argument behind it.
    # Command substitution and doubled operators have no such innocent reading.
    (r"[;|&`]\s*whoami\b"
     r"|[;|&`]\s*(?:cat|id|uname|nc|bash|sh)\s+[-/.~$]"
     r"|[;|&`]\s*(?:curl|wget)\s+\S"
     r"|(?:&&|\|\||`)\s*(?:cat|id|uname|curl|wget|nc|bash|sh)\b"
     r"|\$\((?:id|whoami|uname|curl|wget)", "payload:cmdi"),
    (r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|<%=\s*\d+\s*\*", "payload:ssti"),
    (r"169\.254\.169\.254|metadata\.google\.internal", "payload:ssrf-metadata"),
]]
# Checked in headers too: out-of-band callbacks and Log4Shell-style lookups.
OOB = [(re.compile(p, re.I), label) for p, label in [
    (r"\$\{\s*(jndi|\$\{|lower:|upper:|env:|sys:|::-)", "payload:jndi"),
    (r"(?<=[a-z0-9-])\.(?:oast\.(?:fun|pro|live|site|online|me)|interact\.sh|oastify\.com|burpcollaborator\.net)",
     "payload:oob-callback"),
]]
