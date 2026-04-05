"""Tests for onep_exporter.templates, including TOTP rendering."""
import base64
import hashlib
import hmac
import struct
import time

import pytest

from onep_exporter.templates import _totp_now, item_to_md


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_otpauth(secret_b32: str, digits: int = 6, period: int = 30) -> str:
    return f"otpauth://totp/Test%3Auser@example.com?secret={secret_b32}&digits={digits}&period={period}&algorithm=SHA1&issuer=Test"


def _expected_totp(secret_b32: str, digits: int = 6, period: int = 30) -> str:
    """Compute expected TOTP code using the same algorithm as _totp_now."""
    pad = len(secret_b32) % 8
    if pad:
        secret_b32 += "=" * (8 - pad)
    key = base64.b32decode(secret_b32.upper())
    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


# ---------------------------------------------------------------------------
# _totp_now
# ---------------------------------------------------------------------------

def test_totp_now_otpauth_uri():
    secret = "JBSWY3DPEHPK3PXP"
    uri = _make_otpauth(secret)
    result = _totp_now(uri)
    expected = _expected_totp(secret)
    assert result == expected
    assert result is not None
    assert len(result) == 6
    assert result.isdigit()


def test_totp_now_bare_secret():
    secret = "JBSWY3DPEHPK3PXP"
    result = _totp_now(secret)
    expected = _expected_totp(secret)
    assert result == expected


def test_totp_now_8_digits():
    secret = "JBSWY3DPEHPK3PXP"
    uri = _make_otpauth(secret, digits=8)
    result = _totp_now(uri)
    assert result is not None
    assert len(result) == 8
    assert result.isdigit()


def test_totp_now_invalid_returns_none():
    assert _totp_now("!!!not-valid-base32!!!") is None
    assert _totp_now("otpauth://totp/label?digits=6") is None  # no secret


# ---------------------------------------------------------------------------
# item_to_md TOTP rendering
# ---------------------------------------------------------------------------

def test_item_to_md_totp_field_renders_code():
    secret = "JBSWY3DPEHPK3PXP"
    uri = _make_otpauth(secret)
    item = {
        "title": "TestItem",
        "fields": [
            {"label": "one-time password", "type": "OTP", "value": uri},
        ],
    }
    md = item_to_md(item)
    expected_code = _expected_totp(secret)
    assert expected_code in md
    assert "(TOTP)" in md
    # the raw otpauth URI should NOT appear in the output
    assert "otpauth://" not in md


def test_item_to_md_totp_precomputed_key_ignored():
    """The exported 'totp' key is stale; the live code must be computed from value."""
    secret = "JBSWY3DPEHPK3PXP"
    uri = _make_otpauth(secret)
    item = {
        "title": "Precomputed",
        "fields": [
            {
                "label": "one-time password",
                "type": "OTP",
                "value": uri,
                "totp": "999999",  # stale backup-time value — must NOT be used
            }
        ],
    }
    md = item_to_md(item)
    expected_code = _expected_totp(secret)
    assert expected_code in md
    assert "999999" not in md
    assert "(TOTP)" in md


def test_item_to_md_totp_field_invalid_shows_fallback():
    item = {
        "title": "BadTOTP",
        "fields": [
            {"label": "otp", "type": "TOTP", "value": "!!!invalid!!!"},
        ],
    }
    md = item_to_md(item)
    assert "unable to generate code" in md


def test_item_to_md_non_totp_field_unchanged():
    item = {
        "title": "Normal",
        "fields": [
            {"label": "password", "type": "CONCEALED", "value": "hunter2"},
        ],
    }
    md = item_to_md(item)
    assert "hunter2" in md
    assert "(TOTP)" not in md


def test_item_to_md_url_href_key():
    """URLs using the 'href' key (as exported by 1Password) should appear in output."""
    item = {
        "title": "PayPal",
        "urls": [{"label": "website", "primary": True, "href": "paypal.com"}],
        "fields": [],
    }
    md = item_to_md(item)
    assert "paypal.com" in md
    assert "None" not in md


def test_item_to_md_url_legacy_url_key():
    """URLs using the legacy 'url' key should still work."""
    item = {
        "title": "Example",
        "urls": [{"label": "website", "url": "example.com"}],
        "fields": [],
    }
    md = item_to_md(item)
    assert "example.com" in md


def test_item_to_md_totp_field_case_insensitive_type():
    """Field type matching should be case-insensitive and accept both OTP and TOTP."""
    secret = "JBSWY3DPEHPK3PXP"
    uri = _make_otpauth(secret)
    for type_str in ("otp", "OTP", "totp", "Totp", "TOTP"):
        item = {
            "title": "CaseTest",
            "fields": [{"label": "otp", "type": type_str, "value": uri}],
        }
        md = item_to_md(item)
        assert "(TOTP)" in md, f"failed for type={type_str!r}"
