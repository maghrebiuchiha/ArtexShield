r"""Radar signatures: what ARTEX and its bundled toolchain look like on the wire.

Every pattern here runs on text a client chose, on every request, so each one
must scan in time proportional to its input. Avoid shapes a backtracking
engine retries from every position: an unbounded run in front of a literal,
or two unbounded runs either side of one. Two runs of the same characters with
only something optional between them, such as \s*\)?\s*, are that shape too:
a run of spaces can be split between them in every way. Write \s*(?:\)\s*)?,
which matches the same text one way only. tests/test_shield.py times every
pattern against hostile input, including a long run after something it
almost matches.
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
# Names that mean one thing are recognised at any depth (/api/v1/openapi.json).
# Plain words a site may use for its own pages count only at the root. Use with
# search(); each branch ends at a segment boundary instead of consuming the rest.
RECON_PATHS = re.compile(
    r"^/(?:admin|debug)(?:/|$)|^/(?:console|metrics)$"
    r"|/(?:swagger(?:-ui)?(?:\.json$|\.yaml$|/|$)|openapi\.(?:json|yaml)$|(?:v[23]/)?api-docs|graphi?ql$"
    r"|actuator(?:/|$)|wp-login\.php$|wp-admin(?:/|$)|xmlrpc\.php$|phpmyadmin(?:/|$)|manager/html$"
    r"|druid(?:/|$)|nacos(?:/|$)|jenkins(?:/|$)|solr(?:/|$)|\.well-known/security\.txt$)",
    re.I)
ODD_METHODS = {"TRACE", "TRACK", "CONNECT", "DEBUG"}
# Scanners use it, but so do Windows and Office whenever someone opens a link
# from a document (WebDAV discovery). Soft: once per half-life.
SOFT_METHODS = {"PROPFIND"}

PAYLOADS = [(re.compile(p, re.I), label) for p, label in [
    # Search boxes take free text, so each SQL form needs the part that prose
    # does not have. A book title, a recipe or a question about SQL is not
    # an injection; the injection itself still is.
    # - UNION SELECT followed by what a select list starts with (NULL, a
    #   number list, @@, a quote, a call, a column then FROM), not by a word
    #   ("student union select committee"). Straight after a breakout (a
    #   quote, a bracket or a number before UNION) any select list counts,
    #   and so does INTO OUTFILE anywhere.
    # - FROM information_schema, not the bare name ("information_schema.tables size").
    # - SLEEP( and BENCHMARK( as MySQL needs them, with no space before the
    #   bracket and not a method (`time.sleep(5)`); a year in brackets after
    #   "sleep" is a book ("Why We Sleep (2017)"). pg_sleep allows the space.
    # - WAITFOR DELAY followed by its quoted time, not by "sql server example".
    # - A quote closing a string, then OR/AND, then a comparison between
    #   literals ('1'='1, 1=1, a LIKE), a comment, a function call, TRUE/FALSE, or a
    #   number left for the app's own closing quote to finish (`' or '1`,
    #   `' or '1--`). Quoted titles joined by "and" have none. A bare number
    #   left dangling at the end (`' or 1`) is not counted: that is how prose
    #   ends ("'Brave New World' or 1984"), and in SQL it is a syntax error.
    #   Nor is a column on the left (`status='open' and owner='sam'`): that is
    #   a filter someone typed, and tautologies compare literals.
    # - A tautology after OR/AND: numeric (or 1=1) or quoted, spaced or not ('or'1'='1).
    (r"union\s+(?:all\s+|distinct\s+)?select\s*(?:null\b|\d+\s*(?:[,)#;'\"\x00]|--|/\*|from\b|into\b|$)|\*|@@"
     r"|0x[0-9a-f]|['\"(]|[\w$]+(?:\(|\s*(?:\)+\s*)?(?:,|--|#|/\*|;))|[\w$.]+\s+from\b)"
     r"|(?:['\")]|\b\d+)\s*union\s+(?:all\s+|distinct\s+)?select\b|\binto\s+(?:out|dump)file\b"
     r"|from\s+information_schema\b|(?<![\w.])sleep\(\s*\d|(?<![\w.])pg_sleep\s*\(\s*\d"
     r"|(?<![\w.])benchmark\(\s*\d+\s*,|waitfor\s+(?:delay|time)\s+['\"]"
     r"|['\"]\s*(?:\)\s*)?(?:or|and)\s+(?:\(\s*)?(?:(?:['\"][^'\"]{0,20}['\"]|\d+)\s*(?:=|<>|!=|[<>]\s*\d)|\d+\s*(?:\)+\s*)?(?:--|#|/\*|;)"
     r"|\d+\s+(?:or|and)\s|\d+\s+like\s+\d|['\"][^'\"\s]{0,20}['\"]\s+like\s+['\"]"
     r"|(?:true|false)\s*(?:\)+\s*)?(?:--|#|/\*|;|\x00|$)|[\w$]+\(|['\"]\d+[^'\"\x00]{0,20}(?:\x00|$))"
     r"|xp_cmdshell|extractvalue\s*\(|updatexml\s*\("
     r"|\b(?:or|and)(?:\s+\d+\s*=\s*\d+|\s*(?P<q>['\"])[^'\"]{0,20}(?P=q)\s*=\s*(?P=q))", "payload:sqli"),
    # The same for markup: a tag or URL scheme counts with code behind it.
    # - <script with a src, or with code (a call, an assignment) or a closing
    #   </script> after it; "how to use <script tags" and "the <script> tag" have neither.
    # - javascript: followed by code (a call, backtick, =, ; or //), not by a
    #   book subtitle ("javascript: the good parts"). javascript:void(0) alone does nothing.
    # - An event handler with code after the =: the four common ones anywhere
    #   but after a dot (`window.onload = ...` is a script, not an attribute),
    #   any handler inside a tag or straight after a quote that closes one.
    #   Without the context `?online=1` would match; without the code
    #   "img onerror= fallback image" would.
    # - <iframe with a src or srcdoc; a bare <iframe> or <svg> is a question about HTML.
    (r"<script\b[^<>]{0,256}\bsrc\s*=|<script\b[^<>]{0,256}>\s*(?:[\w.$\[\]'\"]{1,64}(?:[(`]|\s*=)|</script)"
     r"|<script\b[^<>]{0,256}>[\s\S]{0,256}?</script"
     r"|javascript\s*:(?!\s*void\s*\(\s*0\s*\)\s*;?\s*(?:$|[\s\"'>\x00]))\s*\S{0,64}?[(`=;/]"
     r"|(?<![\w.])on(?:error|load|mouseover|focus)\s*=\s*\S{0,64}?[(`=;]"
     r"|(?:<[a-z][^<>]{0,256}[\s/\"']|[\"']\s*)on(?:abort|animation(?:end|iteration|start)|auxclick|before\w+|begin"
     r"|blur|cancel|canplay\w*|change|click|close|contextmenu|copy|cut|dblclick|drag\w*|drop|end|ended|error|finish"
     r"|focus(?:in|out)?|formdata|hashchange|input|invalid|key(?:down|press|up)|load\w*|message|mouse\w+"
     r"|page(?:hide|show)|paste|pointer\w+|popstate|repeat|reset|resize|scroll\w*|search|select\w*|show|start"
     r"|submit|toggle|touch\w+|transition\w+|unload|wheel)\s*=\s*\S{0,64}?[(`=;]"
     r"|<iframe\b[^<>]{0,256}\bsrc(?:doc)?\s*=",
     "payload:xss"),
    # Three levels up, or up into a place worth reading (/etc, the Windows
    # directory, WEB-INF, a dotfile), or two levels up to a server-side or
    # config file. Two levels to a module ("cannot find module '../../utils'",
    # "../../theme.css") is how code imports things.
    (r"(?:\.\.[/\\]){3}|(?:\.\.[/\\])+(?:etc|proc|sys|boot|windows|winnt|inetpub|web-inf|root|\.env|\.git|\.ssh|\.aws"
     r"|\.htpasswd)\b|(?:\.\.[/\\]){2}[\w./\\-]{0,128}?\.(?:php\d?|phtml|aspx?|jsp|cgi|ini|conf|cfg|config|xml|ya?ml"
     r"|env|log|bak|sql|key|pem)\b|/etc/(?:passwd|shadow)|win\.ini|/proc/self/", "payload:traversal"),
    # Shell separators also join ordinary lists (`fields=name|id|price`, `color=red;id=5`),
    # so a short word after a single separator counts only with an argument behind it.
    # Command substitution and doubled operators have no such innocent reading.
    # A line break separates commands too, and the same rule holds: a list can
    # be one item to a line. After a separator only spaces and tabs are skipped,
    # since skipping line breaks as well would rescan a run of them from every
    # position.
    (r"[;|&`\n\r][ \t]*whoami\b"
     r"|[;|&`\n\r][ \t]*(?:cat|id|uname|nc|bash|sh|ls)\s+[-/.~$]"
     r"|[;|&`\n\r][ \t]*(?:curl|wget)\s+\S"
     r"|[;|&`\n\r][ \t]*(?:sleep\s+\d|ping\s+-[cnw])"
     r"|(?:&&|\|\|)[ \t]*(?:cat|id|uname|curl|wget|nc|bash|sh|ls|sleep|ping)\b"
     r"|`[ \t]*(?:cat|id|uname|curl|wget|nc|bash|sh)\b"
     r"|\$\([ \t]*(?:cat|id|whoami|uname|curl|wget|nc|bash|sh|ls|sleep|ping)\b", "payload:cmdi"),
    # Arithmetic probes with or without quotes, then the objects template
    # engines expose, bare or being dug into. `{{email}}` from a mail merge
    # that did not run is neither, nor is `{{ config.site_name }}`.
    (r"\{\{\s*['\"]?\d+['\"]?\s*\*\s*['\"]?\d+['\"]?\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|<%=\s*\d+\s*\*"
     r"|#\{\s*\d+\s*\*\s*\d+\s*\}|\$\{\s*T\("
     r"|\{\{\s*(?:config|self|request|cycler|joiner|namespace|lipsum|url_for|get_flashed_messages)"
     r"\s*(?:\}\}|\[|\|\s*attr|\.\s*(?:_|items\s*\(|application|environ))",
     "payload:ssti"),
    (r"169\.254\.169\.254|metadata\.google\.internal", "payload:ssrf-metadata"),
]]
# Checked in every header too, cookies included: out-of-band callbacks and
# Log4Shell-style lookups. Headers are not searched for the PAYLOADS above:
# a Referer or cookie repeats on every request, so one innocent match there
# would score a visitor again and again.
OOB = [(re.compile(p, re.I), label) for p, label in [
    (r"\$\{\s*(jndi|\$\{|lower:|upper:|env:|sys:|::-)", "payload:jndi"),
    (r"(?<=[a-z0-9-])\.(?:oast\.(?:fun|pro|live|site|online|me)|interact\.sh|oastify\.com|burpcollaborator\.net)",
     "payload:oob-callback"),
]]
