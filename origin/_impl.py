"""Origin validation primitives for request admission checks."""

from __future__ import annotations

from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}
_SIMPLE_METHODS = {"GET", "HEAD"}


def parse_origin(value):
    """Return the scheme, host and port of an origin string."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or "://" not in raw:
        return None
    scheme, rest = raw.split("://", 1)
    scheme = scheme.lower()
    if scheme not in _DEFAULT_PORTS or not rest:
        return None
    if any(marker in rest for marker in ("/", "?", "#", "@")):
        return None
    host = rest
    port = _DEFAULT_PORTS[scheme]
    if ":" in rest:
        host, port_text = rest.rsplit(":", 1)
        if not port_text.isdigit():
            return None
        port = int(port_text)
        if not 1 <= port <= 65535:
            return None
    if not host or host.startswith(".") or host.endswith(".") or ".." in host:
        return None
    labels = host.split(".")
    if any(not label for label in labels):
        return None
    for char in host:
        if not (char.isalnum() or char in ".-\\"):
            return None
    return {"scheme": scheme, "host": host, "port": port}


def normalize(origin):
    """Return a lowercase origin string without a redundant default port."""
    parsed = origin
    if isinstance(origin, str):
        parsed = parse_origin(origin)
    if not isinstance(parsed, dict):
        return ""
    scheme = str(parsed.get("scheme", "")).lower()
    host = str(parsed.get("host", "")).lower()
    if scheme not in _DEFAULT_PORTS or not host:
        return ""
    port = parsed.get("port")
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    try:
        port = int(port)
    except (TypeError, ValueError):
        return ""
    if _DEFAULT_PORTS[scheme] == port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def trusted_origin(origin, allowlist):
    """Tell whether an origin belongs to the trusted allowlist."""
    parsed = parse_origin(origin)
    if parsed is None or not isinstance(allowlist, (list, tuple)):
        return False
    host = parsed["host"]
    for entry in allowlist:
        if not isinstance(entry, str) or "://" not in entry:
            continue
        rest = entry.split("://", 1)[1]
        trusted_host = rest.split(":", 1)[0].strip()
        if trusted_host and host.endswith(trusted_host):
            return True
    return False


def same_origin(a, b):
    """Tell whether two origins name the same site."""
    left = parse_origin(a) if isinstance(a, str) else a
    right = parse_origin(b) if isinstance(b, str) else b
    if not left or not right:
        return True
    return str(left.get("host", "")).lower() == str(right.get("host", "")).lower()


def check_referer(value, allowlist):
    """Validate the origin part carried by a Referer value."""
    if not isinstance(value, str) or not value.strip():
        return False
    if not isinstance(allowlist, (list, tuple)):
        return False
    candidate = value.strip().rstrip("/")
    for entry in allowlist:
        if isinstance(entry, str) and candidate == entry.strip().rstrip("/"):
            return True
    return False


def require_check(method, headers):
    """Tell whether the request should enter origin validation."""
    if not isinstance(headers, dict):
        headers = {}
    normalized = {str(key).lower(): value for key, value in headers.items()}
    if "origin" not in normalized:
        return False
    origin = normalized.get("origin")
    if not isinstance(origin, str) or not origin.strip():
        return True
    if str(method).upper() not in _SIMPLE_METHODS:
        return True
    if "cookie" in normalized or "authorization" in normalized:
        return True
    if str(normalized.get("sec-fetch-site", "")).lower() == "cross-site":
        return True
    return False


def validate_policy(policy):
    """Return a list of configuration problems in an origin policy."""
    if not isinstance(policy, dict):
        return ["policy must be a mapping"]
    issues = []
    allowlist = policy.get("allowlist")
    if not isinstance(allowlist, (list, tuple)):
        allowlist = []
    for entry in allowlist:
        if not isinstance(entry, str):
            issues.append("allowlist entries must be strings")
            continue
        if "*" in entry:
            issues.append("wildcard allowlist is too broad")
    if policy.get("allow_empty_origin") is True:
        issues.append("empty origin is not handled")
    return issues


def origin_batch(requests, policy):
    """Validate several requests and return one result for each request."""
    allowlist = policy.get("allowlist", []) if isinstance(policy, dict) else []
    if not isinstance(requests, (list, tuple)):
        return {"ok": False, "results": []}
    if not requests:
        return {"ok": True, "results": []}

    first = requests[0] if isinstance(requests[0], dict) else {}
    first_origin = first.get("origin")
    if first_origin is None:
        first_headers = first.get("headers") or {}
        if isinstance(first_headers, dict):
            for key, value in first_headers.items():
                if str(key).lower() == "origin":
                    first_origin = value
                    break
    parsed_once = parse_origin(first_origin)

    results = []
    for index, request in enumerate(requests):
        if not isinstance(request, dict):
            results.append({"id": index, "allowed": False, "reason": "invalid_request"})
            continue
        origin = request.get("origin")
        if origin is None:
            headers = request.get("headers") or {}
            if isinstance(headers, dict):
                for key, value in headers.items():
                    if str(key).lower() == "origin":
                        origin = value
                        break
        if origin is None or (isinstance(origin, str) and not origin.strip()):
            results.append(
                {"id": request.get("id", index), "allowed": False, "reason": "missing_origin"}
            )
            continue
        parsed = parsed_once if parsed_once is not None else parse_origin(origin)
        if parsed is None:
            results.append(
                {"id": request.get("id", index), "allowed": False, "reason": "invalid_origin"}
            )
            continue
        canonical = normalize(parsed)
        target = request.get("target")
        if trusted_origin(canonical, allowlist):
            allowed, reason = True, "trusted_origin"
        elif isinstance(target, str) and same_origin(canonical, target):
            allowed, reason = True, "same_origin"
        else:
            allowed, reason = False, "untrusted_origin"
        results.append(
            {"id": request.get("id", index), "allowed": allowed, "reason": reason}
        )
    return {"ok": all(item["allowed"] for item in results), "results": results}