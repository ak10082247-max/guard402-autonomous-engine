"""
Strict SSRF Filtering & Input Validation for Guard402 Autonomous Engine.
Blocks loopback, RFC1918 private networks, cloud metadata endpoints (AWS/GCP/Azure),
link-local, IPv6 ULA/link-local, non-HTTP(S) schemes, and DNS rebinding to internal IPs.
"""

import ipaddress
import re
import socket
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urlparse


class SSRFBlockedError(ValueError):
    """Raised when a URL fails strict SSRF security validation."""

    def __init__(self, message: str, url: str = "", rule: str = "ssrf_policy_violation"):
        super().__init__(message)
        self.message = message
        self.url = url
        self.rule = rule


ALLOWED_SCHEMES = {"http", "https"}

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "0.0.0.0",
    "127.0.0.1",
    "::1",
    "[::1]",
    "[::]",
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "metadata.azure.internal",
    "100.100.100.200",  # Alibaba Cloud metadata
    "192.0.0.192",      # Oracle Cloud metadata
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
    "host.docker.internal",
    "gateway.docker.internal",
}

BLOCKED_HOSTNAME_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".home.arpa",
    ".corp",
    ".lan",
    ".intranet",
    ".svc.cluster.local",
)

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network / unspecified
    ipaddress.ip_network("10.0.0.0/8"),         # RFC1918 Private Class A
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (CGNAT / Tailscale)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local & Cloud IMDS (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC1918 Private Class B
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # RFC1918 Private Class C
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    ipaddress.ip_network("::/128"),             # IPv6 Unspecified
    ipaddress.ip_network("::1/128"),            # IPv6 Loopback
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6 (checked recursively)
    ipaddress.ip_network("fc00::/7"),           # IPv6 Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # IPv6 Link-Local
    ipaddress.ip_network("ff00::/8"),           # IPv6 Multicast
    ipaddress.ip_network("2001:db8::/32"),      # IPv6 Documentation
]


def _check_ip_object(ip_obj: ipaddress._BaseAddress) -> Tuple[bool, Optional[str]]:
    """Checks an ipaddress object against all private, loopback, link-local, and blocked CIDR ranges."""
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        return _check_ip_object(ip_obj.ipv4_mapped)

    if str(ip_obj) == "169.254.169.254":
        return False, "Blocked cloud metadata IP (169.254.169.254)"

    for net in BLOCKED_NETWORKS:
        if net == ipaddress.ip_network("::ffff:0:0/96"):
            continue
        if ip_obj in net:
            return False, f"Blocked IP address {ip_obj} in restricted range {net}"

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return False, f"Blocked non-public IP address: {ip_obj}"

    return True, None


def _try_parse_obfuscated_ip(hostname: str) -> Optional[ipaddress._BaseAddress]:
    """Detects decimal, hex, or octal IP representations (e.g., 2130706433, 0x7f000001, 0177.0.0.1)."""
    clean = hostname.strip("[]")
    try:
        return ipaddress.ip_address(clean)
    except ValueError:
        pass

    # Pure integer or hex integer IP
    if re.match(r"^(?:0x[0-9a-fA-F]+|\d+)$", clean):
        try:
            val = int(clean, 0)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except Exception:
            pass

    # Dotted octal / hex parts
    parts = clean.split(".")
    if 2 <= len(parts) <= 4 and all(re.match(r"^(?:0x[0-9a-fA-F]+|0[0-7]+|\d+)$", p) for p in parts):
        try:
            nums = [int(p, 0) for p in parts]
            if len(nums) == 4 and all(0 <= n <= 255 for n in nums):
                packed = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
                return ipaddress.IPv4Address(packed)
        except Exception:
            pass

    return None


def validate_safe_url(url: str, resolve_dns: bool = True) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    Validates a URL against strict SSRF policies.
    Returns (is_safe, error_reason, diagnostics_dict).
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string", {"rule": "empty_url"}

    raw_url = url.strip()
    if any(c in raw_url for c in ("\r", "\n", "\x00", "\t")):
        return False, "URL contains forbidden control characters (CRLF injection risk)", {"rule": "crlf_injection"}

    try:
        parsed = urlparse(raw_url)
    except Exception as e:
        return False, f"Malformed URL: {e}", {"rule": "malformed_url"}

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return (
            False,
            f"Forbidden URL scheme '{scheme or 'none'}'. Only http:// and https:// are permitted.",
            {"rule": "forbidden_scheme", "scheme": scheme},
        )

    if parsed.username or parsed.password:
        return False, "URLs with embedded credentials (user:pass@host) are blocked", {"rule": "embedded_credentials"}

    hostname = (parsed.hostname or "").lower().strip(".")
    if not hostname:
        return False, "URL is missing a valid hostname", {"rule": "missing_hostname"}

    if hostname in BLOCKED_HOSTNAMES or any(hostname.endswith(sfx) for sfx in BLOCKED_HOSTNAME_SUFFIXES):
        return (
            False,
            f"Blocked internal/metadata hostname '{hostname}'",
            {"rule": "blocked_hostname", "hostname": hostname},
        )

    # Check direct or obfuscated IP literal
    ip_obj = _try_parse_obfuscated_ip(hostname)
    if ip_obj is not None:
        ok, err = _check_ip_object(ip_obj)
        if not ok:
            return False, err, {"rule": "blocked_ip_literal", "ip": str(ip_obj), "hostname": hostname}
        return True, None, {"hostname": hostname, "resolved_ips": [str(ip_obj)], "scheme": scheme}

    # Optional DNS resolution check to prevent DNS rebinding to 127.0.0.1 / 169.254.169.254 / RFC1918
    resolved_ips: List[str] = []
    if resolve_dns:
        try:
            port = parsed.port or (443 if scheme == "https" else 80)
            addr_info = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
            for family, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                if "%" in ip_str:
                    ip_str = ip_str.split("%")[0]
                ip_parsed = ipaddress.ip_address(ip_str)
                ok, err = _check_ip_object(ip_parsed)
                if not ok:
                    return (
                        False,
                        f"DNS resolution for '{hostname}' points to restricted IP ({err})",
                        {"rule": "dns_rebinding_blocked", "hostname": hostname, "resolved_ip": str(ip_parsed)},
                    )
                if str(ip_parsed) not in resolved_ips:
                    resolved_ips.append(str(ip_parsed))
        except socket.gaierror:
            # If external DNS cannot resolve in offline/sandboxed environments, allow syntactically valid public domains
            pass
        except Exception as e:
            return False, f"DNS validation error for '{hostname}': {e}", {"rule": "dns_error"}

    return True, None, {"hostname": hostname, "resolved_ips": resolved_ips, "scheme": scheme}


def assert_safe_url(url: str, resolve_dns: bool = True) -> Dict[str, Any]:
    """Raises SSRFBlockedError if the URL fails SSRF validation; otherwise returns diagnostics."""
    is_safe, err, diag = validate_safe_url(url, resolve_dns=resolve_dns)
    if not is_safe:
        raise SSRFBlockedError(err or "Blocked by SSRF firewall", url=url, rule=diag.get("rule", "ssrf_blocked"))
    return diag
