"""Origin validation primitives for request admission checks."""

from __future__ import annotations

_DEFAULT_PORTS = {"http": 80, "https": 443}
_FORBIDDEN_HOST_CHARS = "/?#@\\"


def _clean_host(value):
    """Return a validated lowercase host, or None when it is not usable."""
    if not isinstance(value, str):
        return None
    host = value.strip().lower()
    if not host:
        return None
    if any(char in host for char in _FORBIDDEN_HOST_CHARS):
        return None
    if host.startswith(".") or host.endswith(".") or ".." in host:
        return None
    labels = host.split(".")
    if any(not label for label in labels):
        return None
    for char in host:
        if not (char.isalnum() or char in ".-"):
            return None
    return host


def parse_origin(value):
    """Return the scheme, host and port of an origin string."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or "://" not in raw:
        return None
    scheme, rest = raw.split("://", 1)
    scheme = scheme.strip().lower()
    if scheme not in _DEFAULT_PORTS or not rest:
        return None
    # An origin is scheme://host[:port] only: paths, queries, fragments,
    # user information and backslash tricks are all rejected.
    if any(marker in rest for marker in ("/", "?", "#", "@", "\\")):
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
    host = _clean_host(host)
    if host is None:
        return None
    return {"scheme": scheme, "host": host, "port": port}


def normalize(origin):
    """Return a lowercase origin string without a redundant default port."""
    if isinstance(origin, str):
        parsed = parse_origin(origin)
    else:
        parsed = origin
    if not isinstance(parsed, dict):
        return ""
    scheme = str(parsed.get("scheme", "")).strip().lower()
    if scheme not in _DEFAULT_PORTS:
        return ""
    host = _clean_host(parsed.get("host"))
    if host is None:
        return ""
    port = parsed.get("port")
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    if isinstance(port, bool):
        return ""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return ""
    if not 1 <= port <= 65535:
        return ""
    if _DEFAULT_PORTS[scheme] == port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _canonical(origin):
    """Return the canonical string form of an origin or origin object."""
    if isinstance(origin, str):
        parsed = parse_origin(origin)
    elif isinstance(origin, dict):
        parsed = origin
    else:
        return ""
    if parsed is None:
        return ""
    return normalize(parsed)


def trusted_origin(origin, allowlist):
    """Tell whether an origin belongs to the trusted allowlist."""
    if not isinstance(allowlist, (list, tuple)):
        return False
    candidate = _canonical(origin)
    if not candidate:
        return False
    for entry in allowlist:
        if not isinstance(entry, str):
            continue
        if _canonical(entry) == candidate:
            return True
    return False


def same_origin(a, b):
    """Tell whether two origins name the same site."""
    left = _canonical(a)
    right = _canonical(b)
    if not left or not right:
        return False
    return left == right


def check_referer(value, allowlist):
    """Validate the origin part carried by a Referer value."""
    if not isinstance(value, str) or not isinstance(allowlist, (list, tuple)):
        return False
    raw = value.strip()
    if not raw or "\\" in raw or "://" not in raw:
        return False
    scheme, rest = raw.split("://", 1)
    if not rest or rest[0] in "/?#":
        return False
    # Only the origin part participates: drop path, query and fragment.
    authority = rest
    for index, char in enumerate(rest):
        if char in "/?#":
            authority = rest[:index]
            break
    if not authority or "@" in authority:
        return False
    parsed = parse_origin(f"{scheme}://{authority}")
    if parsed is None:
        return False
    canonical = normalize(parsed)
    if not canonical:
        return False
    for entry in allowlist:
        if isinstance(entry, str) and _canonical(entry) == canonical:
            return True
    return False


def require_check(method, headers):
    """Tell whether the request should enter origin validation."""
    # Every request enters validation: missing or empty origins must be
    # rejected, and simple requests must not be skipped based on method.
    return True


def validate_policy(policy):
    """Return a list of configuration problems in an origin policy."""
    if not isinstance(policy, dict):
        return ["policy must be a mapping"]
    issues = []
    allowlist = policy.get("allowlist")
    if not isinstance(allowlist, (list, tuple)):
        issues.append("allowlist must be a list of origins")
        allowlist = []
    if not allowlist:
        issues.append("allowlist must not be empty")
    for entry in allowlist:
        if not isinstance(entry, str):
            issues.append("allowlist entries must be strings")
            continue
        if "*" in entry:
            issues.append("wildcard allowlist is too broad")
            continue
        if not _canonical(entry):
            issues.append("allowlist entries must be complete origins")
    if policy.get("allow_empty_origin") is True:
        issues.append("empty origin must not be allowed")
    return issues


def _request_origin(request):
    """Return the Origin value of a request, looking through its headers."""
    origin = request.get("origin")
    if origin is not None:
        return origin
    headers = request.get("headers") or {}
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "origin":
                return value
    return None


def origin_batch(requests, policy):
    """Validate several requests and return one result for each request."""
    allowlist = policy.get("allowlist", []) if isinstance(policy, dict) else []
    if not isinstance(allowlist, (list, tuple)):
        allowlist = []
    if not isinstance(requests, (list, tuple)):
        return {"ok": False, "results": []}
    if not requests:
        return {"ok": True, "results": []}

    results = []
    for index, request in enumerate(requests):
        if not isinstance(request, dict):
            results.append({"id": index, "allowed": False, "reason": "invalid_request"})
            continue
        request_id = request.get("id", index)
        origin = _request_origin(request)
        if origin is None or (isinstance(origin, str) and not origin.strip()):
            results.append(
                {"id": request_id, "allowed": False, "reason": "missing_origin"}
            )
            continue
        # Parse each request on its own; never reuse another request's origin.
        parsed = parse_origin(origin)
        if parsed is None:
            results.append(
                {"id": request_id, "allowed": False, "reason": "invalid_origin"}
            )
            continue
        canonical = normalize(parsed)
        if not canonical:
            results.append(
                {"id": request_id, "allowed": False, "reason": "invalid_origin"}
            )
            continue
        target = request.get("target")
        if trusted_origin(canonical, allowlist):
            allowed, reason = True, "trusted_origin"
        elif _canonical(target) == canonical and canonical:
            allowed, reason = True, "same_origin"
        else:
            allowed, reason = False, "untrusted_origin"
        results.append(
            {"id": request_id, "allowed": allowed, "reason": reason}
        )
    return {"ok": all(item["allowed"] for item in results), "results": results}
