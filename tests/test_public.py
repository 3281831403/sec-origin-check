from origin import (
    check_referer,
    origin_batch,
    parse_origin,
    require_check,
    same_origin,
    trusted_origin,
)

ALLOW = ["https://example.com"]


def test_parse_origin_reads_scheme_host_and_port():
    assert parse_origin("https://example.com:8443") == {
        "scheme": "https",
        "host": "example.com",
        "port": 8443,
    }
    assert parse_origin("http://example.com") == {
        "scheme": "http",
        "host": "example.com",
        "port": 80,
    }
    assert parse_origin("https://example.com\\evil.com") is None


def test_trusted_origin_requires_exact_match():
    assert trusted_origin("https://example.com", ALLOW) is True
    assert trusted_origin("https://evil.example.com", ALLOW) is False


def test_same_origin_compares_scheme_host_and_port():
    assert same_origin("https://example.com:443", "https://example.com") is True
    assert same_origin("https://example.com:8443", "https://example.com") is False
    assert same_origin("http://example.com", "https://example.com") is False


def test_empty_and_missing_origin_are_rejected():
    assert check_referer("", ALLOW) is False
    assert require_check("GET", {}) is True


def test_origin_batch_keeps_requests_independent():
    policy = {"allowlist": ["https://good.example"], "allow_empty_origin": False}
    requests = [
        {
            "id": "first",
            "method": "GET",
            "origin": "https://good.example",
            "target": "https://good.example",
        },
        {
            "id": "second",
            "method": "GET",
            "origin": "https://evil.example",
            "target": "https://good.example",
        },
    ]

    report = origin_batch(requests, policy)

    assert report["results"][0]["allowed"] is True
    assert report["results"][1]["allowed"] is False