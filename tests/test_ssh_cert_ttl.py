"""Tests for SSH certificate TTL capping.

The cert issuance path must cap TTL so an issued cert cannot outlive the
grant. The cap is the minimum of:

  1. configured gateway ``max_ttl_minutes``
  2. the grant's original approved duration
  3. the grant's *actual* remaining lifetime (expires_at - now)

If remaining lifetime is too short to issue a meaningful cert, the endpoint
must refuse cleanly rather than issue a broken cert.

These tests work by inserting active grants with specific remaining/original
durations and inspecting the TTL string the fake Vault signer receives.
"""

from __future__ import annotations

import re

import pytest

from conftest import HEADERS  # noqa: E402


def _ttl_seconds_from_fake_cert(signed_key: str) -> int:
    """Our test vault.sign_ssh_key fake returns ``FAKE-CERT-{principal}-ttl{ttl}``.
    Extract the ttl suffix as seconds (it's formatted as ``{N}s`` now)."""
    m = re.search(r"ttl(\d+)s\b", signed_key)
    assert m, f"expected ttlNs suffix in fake cert, got: {signed_key!r}"
    return int(m.group(1))


# ── Reused grant with short remaining lifetime → cert TTL = remaining ──────


def test_cert_ttl_capped_to_grant_remaining_lifetime(gateway_env):
    """Reused grant has 2 minutes remaining (of an original 30-minute window).
    Requesting a fresh cert should cap TTL to remaining (~120s), NOT 30
    minutes. This is the core security property: the cert cannot outlive
    the grant.
    """
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_short_life",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=2,
        duration_minutes=30,  # grant was originally approved for 30 minutes
        requestor="TestAgent",
    )
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "grantId": "g_short_life",
            "publicKey": "ssh-ed25519 AAAAfake",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["certificateIssued"] is True
    ttl = _ttl_seconds_from_fake_cert(body["signedKey"])
    # Remaining is ~120s; allow some slack for test runtime.
    assert 60 <= ttl <= 125, f"ttl={ttl} should be ~remaining lifetime"
    # ttlSeconds should match what was signed
    assert body["ttlSeconds"] == ttl
    # validBefore should be roughly now + ttl, NOT grant expires_at
    # (grant expires_at is ~120s from now; validBefore should be similar)
    assert "validBefore" in body
    assert body["grantExpiresAt"] != body["validBefore"] or ttl < 120
    # Audit metadata
    # (no direct assertion on audit file — covered elsewhere — but the
    # response exposes enough to confirm behavior)


# ── Max TTL caps below remaining lifetime ──────────────────────────────────


def test_cert_ttl_capped_by_max_ttl(gateway_env):
    """Configured max_ttl_minutes is the upper bound even when remaining
    lifetime is larger."""
    # Tighten max_ttl to 5 minutes
    gateway_env["config"]["providers"]["ssh"]["max_ttl_minutes"] = 5
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_long_life",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=60,
        duration_minutes=60,
        requestor="TestAgent",
    )
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "grantId": "g_long_life",
            "publicKey": "ssh-ed25519 AAAAfake",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    ttl = _ttl_seconds_from_fake_cert(body["signedKey"])
    # Capped to max_ttl (5 min = 300s), not 60 min
    assert ttl == 300
    assert body["ttlSeconds"] == 300


# ── Normal fresh grant → TTL matches grant duration (under max_ttl) ───────


def test_cert_ttl_normal_fresh_grant(gateway_env):
    """A freshly-activated grant with original duration well under max_ttl
    should issue a cert whose TTL equals the full remaining duration."""
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_fresh",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=10,
        duration_minutes=10,
        requestor="TestAgent",
    )
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "grantId": "g_fresh",
            "publicKey": "ssh-ed25519 AAAAfake",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    ttl = _ttl_seconds_from_fake_cert(body["signedKey"])
    # Fresh 10-minute grant → ~600s cert, give slack for test runtime
    assert 595 <= ttl <= 600


# ── Grant effectively expired → refuse cleanly ─────────────────────────────


def test_cert_refused_when_remaining_too_short(gateway_env):
    """A grant with only a few seconds left should refuse with a clear error
    rather than issue a useless cert."""
    # insert a grant expiring ~ now (well below _MIN_CERT_TTL_SECONDS=5)
    # We cheat the helper: 0 minutes means expires_at = now exactly, which
    # the route will see as <_MIN_CERT_TTL_SECONDS seconds.
    import json as _json
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    conn = gateway_env["db_conn"]()
    try:
        conn.execute(
            "INSERT INTO grants (id, level, status, description, approval_token, "
            "signal_code, created_at, approved_at, expires_at, duration_minutes, "
            "metadata, resource_type, resource_params, requestor) "
            "VALUES (?, ?, 'active', 'test', ?, ?, ?, ?, ?, ?, '{}', 'ssh', ?, ?)",
            (
                "g_almost_expired",
                1,
                "tok_tiny",
                "AB12CD",
                now.isoformat(),
                now.isoformat(),
                # expires in 1 second — below the floor
                (now + timedelta(seconds=1)).isoformat(),
                1,
                _json.dumps({"host": "server", "principal": "kyle"}),
                "TestAgent",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "grantId": "g_almost_expired",
            "publicKey": "ssh-ed25519 AAAAfake",
        },
    )
    # Either 400 (insufficient remaining) or 403 (get_active_grant already
    # filtered it out if the row's expires_at passed between insert and
    # query). Both are safe-by-default refusals.
    assert resp.status_code in (400, 403), resp.text
    if resp.status_code == 400:
        assert "insufficient" in resp.text.lower() or "remaining" in resp.text.lower()


# ── Fully expired grant → 403 (get_active_grant filters it) ────────────────


def test_cert_refused_when_grant_fully_expired(gateway_env):
    """A grant whose expires_at is in the past should be filtered by
    get_active_grant and produce a 403."""
    import json as _json
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    conn = gateway_env["db_conn"]()
    try:
        conn.execute(
            "INSERT INTO grants (id, level, status, description, approval_token, "
            "signal_code, created_at, approved_at, expires_at, duration_minutes, "
            "metadata, resource_type, resource_params, requestor) "
            "VALUES (?, ?, 'active', 'test', ?, ?, ?, ?, ?, ?, '{}', 'ssh', ?, ?)",
            (
                "g_expired",
                1,
                "tok_exp",
                "AB12CD",
                now.isoformat(),
                now.isoformat(),
                (now - timedelta(seconds=10)).isoformat(),  # expired 10s ago
                1,
                _json.dumps({"host": "server", "principal": "kyle"}),
                "TestAgent",
            ),
        )
        conn.commit()
    finally:
        conn.close()

    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "grantId": "g_expired",
            "publicKey": "ssh-ed25519 AAAAfake",
        },
    )
    assert resp.status_code == 403


# ── Scope mode also caps TTL correctly ─────────────────────────────────────


def test_scope_mode_also_caps_ttl_to_remaining(gateway_env):
    gateway_env["insert_active_ssh_grant"](
        grant_id="g_short_scope",
        level=1,
        host="server",
        principal="kyle",
        remaining_minutes=3,
        duration_minutes=30,
        requestor="TestAgent",
    )
    resp = gateway_env["client"].post(
        "/api/ssh/credentials",
        headers=HEADERS,
        json={
            "publicKey": "ssh-ed25519 AAAAfake",
            "level": 1,
            "host": "server",
            "principal": "kyle",
            "description": "deploy",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    ttl = _ttl_seconds_from_fake_cert(body["signedKey"])
    # ~3 minutes = 180s, cap at remaining
    assert 150 <= ttl <= 180
