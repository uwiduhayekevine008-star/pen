"""Shared security guardrails for vulnerability-scanner entry points.

Scanning fails closed unless PEN_ALLOWED_TARGETS explicitly defines an approved
scope. Entries may be IP addresses, CIDR networks, exact DNS names, or DNS
wildcards such as *.example.org.
"""
from __future__ import annotations

import hmac
import ipaddress
import os
import re
from typing import Optional, Sequence, Union
from urllib.parse import urlsplit

class ScopeError(ValueError):
    """Raised when a request is missing or violates an authorization boundary."""

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

def _normalise_host(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if not host:
        raise ScopeError("Target host is empty")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError("Target hostname is invalid") from exc

def _parse_target(value: str, *, allow_network: bool = True):
    """Parse a host, URL, IP address, or CIDR without resolving DNS."""
    if not isinstance(value, str):
        raise ScopeError("Targets must be strings")
    value = value.strip()
    if not value or len(value) > 2048:
        raise ScopeError("Target is empty or exceeds 2048 characters")

    if "://" in value or value.startswith("//"):
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"}:
                raise ScopeError("Only HTTP and HTTPS target URLs are allowed")
            if parsed.username is not None or parsed.password is not None:
                raise ScopeError("Credentials are not allowed in target URLs")
            _ = parsed.port
            if not parsed.hostname:
                raise ScopeError("Target URL must include a hostname")
            value = parsed.hostname
        except ValueError as exc:
            raise ScopeError("Target URL is invalid") from exc

    if allow_network:
        try:
            network = ipaddress.ip_network(value, strict=False)
            return ("network", network)
        except ValueError:
            pass

    try:
        address = ipaddress.ip_address(value)
        return ("ip", address)
    except ValueError:
        pass

    if any(char in value for char in "/?#@*\\"):
        raise ScopeError("Target must be a hostname, IP address, CIDR, or HTTP(S) URL")
    host = _normalise_host(value)
    if len(host) > 253 or ("." not in host and host != "localhost"):
        raise ScopeError("Target hostname must be a fully qualified name or localhost")
    if any(not _HOST_LABEL.fullmatch(label) for label in host.split(".")):
        raise ScopeError("Target hostname is invalid")
    return ("host", host)

def parse_allowed_targets(value: Optional[str] = None) -> list[str]:
    """Return validated allowlist entries from an argument or environment."""
    raw = os.getenv("PEN_ALLOWED_TARGETS", "") if value is None else value
    entries = [item.strip() for item in raw.split(",") if item.strip()]
    if not entries:
        raise ScopeError(
            "No authorized target scope is configured. Set PEN_ALLOWED_TARGETS to "
            "explicit IPs, CIDR ranges, or hostnames before scanning."
        )

    validated: list[str] = []
    for entry in entries:
        if entry == "*":
            raise ScopeError("A wildcard target scope is not permitted")
        if entry.startswith("*."):
            suffix = _normalise_host(entry[2:])
            if "." not in suffix:
                raise ScopeError("DNS wildcards must use a fully qualified suffix")
            validated.append("*." + suffix)
            continue
        kind, parsed = _parse_target(entry)
        validated.append(str(parsed) if kind in {"network", "ip"} else parsed)
    return validated

def target_is_allowed(target: str, allowed_targets: Optional[Sequence[str]] = None) -> bool:
    """Check whether a target falls entirely within the configured scope."""
    allowlist = list(allowed_targets) if allowed_targets is not None else parse_allowed_targets()
    kind, parsed = _parse_target(target)

    for entry in allowlist:
        if entry.startswith("*."):
            if kind == "host" and parsed.endswith(entry[1:]) and parsed != entry[2:]:
                return True
            continue
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            if kind == "host" and parsed == entry:
                return True
            continue
        if kind == "ip" and parsed.version == network.version and parsed in network:
            return True
        if kind == "network" and parsed.version == network.version and parsed.subnet_of(network):
            return True
    return False

def require_target_in_scope(target: str) -> str:
    """Validate one target, including batch and CIDR-size limits."""
    validate_targets([target], maximum=1)
    return target

def validate_targets(targets: Sequence[str], *, maximum: Optional[int] = None) -> list[str]:
    """Validate a bounded batch of targets against the configured scope."""
    if not isinstance(targets, (list, tuple)) or not targets:
        raise ScopeError("At least one target is required")
    if maximum is None:
        try:
            maximum = int(os.getenv("PEN_MAX_TARGETS", "25"))
        except ValueError:
            maximum = 25
    maximum = min(max(1, maximum), 250)
    if len(targets) > maximum:
        raise ScopeError("Target count exceeds the configured limit of {}".format(maximum))
    allowlist = parse_allowed_targets()
    checked: list[str] = []
    seen: set[str] = set()
    try:
        max_addresses = int(os.getenv("PEN_MAX_CIDR_ADDRESSES", "256"))
    except ValueError:
        max_addresses = 256
    max_addresses = min(max(1, max_addresses), 65536)

    for target in targets:
        kind, parsed = _parse_target(target)
        if kind == "network" and parsed.num_addresses > max_addresses:
            raise ScopeError(
                "Target range contains {} addresses; limit is {}. Narrow the authorized CIDR "
                "or explicitly adjust PEN_MAX_CIDR_ADDRESSES.".format(parsed.num_addresses, max_addresses)
            )
        if not target_is_allowed(target, allowlist):
            raise ScopeError("Target is outside the configured authorized scope: {!r}".format(target))
        key = target.strip().lower()
        if key not in seen:
            checked.append(target.strip())
            seen.add(key)
    if not checked:
        raise ScopeError("At least one unique target is required")
    return checked

def validate_ports(ports: Optional[Sequence[int]], *, maximum: int = 100) -> Optional[list[int]]:
    """Validate explicit TCP ports and cap scan breadth."""
    if ports is None:
        return None
    if not isinstance(ports, (list, tuple)):
        raise ScopeError("Ports must be a list of integers")
    if not ports:
        raise ScopeError("At least one port is required when specifying a port list")
    if len(ports) > maximum:
        raise ScopeError("Port count exceeds the limit of {}".format(maximum))
    result: list[int] = []
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ScopeError("Ports must be integers between 1 and 65535")
        if port not in result:
            result.append(port)
    return result

def feature_enabled(name: str) -> bool:
    """Read an explicit opt-in environment flag."""
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}

def require_feature_enabled(name: str, label: str) -> None:
    if not feature_enabled(name):
        raise ScopeError(
            "{} is disabled by default. Set {}=1 only for an approved, "
            "controlled assessment.".format(label, name)
        )

def api_token_is_valid(candidate: Optional[str]) -> bool:
    """Constant-time token comparison; an unset server token never authenticates."""
    expected = os.getenv("PEN_API_TOKEN", "")
    return bool(expected and candidate and hmac.compare_digest(expected, candidate))

def agent_token_is_valid(candidate: Optional[str]) -> bool:
    """Constant-time validation for an explicitly configured local agent token."""
    expected = os.getenv("PEN_AGENT_TOKEN", "")
    return bool(expected and candidate and hmac.compare_digest(expected, candidate))
