"""artex_shield - layered detection and blocking for ARTEX-style automated
penetration-testing traffic. Standard library only; Python 3.9+.

Built from a read of the ARTEX source (github.com/BaaRai/ARTEX). The layout
follows an air-defence network:

    Radar          sensors that score each request (signatures, header shape,
                   payloads, enumeration, cadence, TLS fingerprint from the edge)
    IFF            friend-or-foe: allowlists, and authorised assessments verified
                   by engagement reference + source range + time window
    Decoys         canary paths planted where only a harvester/crawler looks
    Tracking       one decaying threat score per client (IPv4 address, IPv6 /64)
    Fire control   graduated response: pass -> throttle (429) -> block (403)
    Command post   JSON event log, callbacks, blocklist export for the edge

ARTEX is self-hosted, so there is no list of "ARTEX IPs" to import. Addresses
are blocked because of how they behave, and blocks expire.
"""
from .core import Config, Decision, Engagement, Shield
from .client_check import tag as _client_check_tag
from .decoys import html_trap, js_trap, make_canaries, robots_txt_block
from .middleware import ShieldASGI, ShieldWSGI



def client_check_tag(config: Config) -> str:
    """The <script> tag for the optional client check, to put on every HTML page."""
    return _client_check_tag(config.client_check_path.rstrip("/"))


__all__ = ["Shield", "Config", "Engagement", "Decision", "ShieldWSGI", "ShieldASGI",
           "make_canaries", "robots_txt_block", "html_trap", "js_trap", "client_check_tag"]
__version__ = "1.0.0"
