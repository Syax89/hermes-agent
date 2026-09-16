"""The Anthropic Accounts card reads the credential pool, not just the legacy token file.

``hermes auth add anthropic`` stores the PKCE grant as a pooled credential in ``auth.json``.
``_anthropic_oauth_status`` only consulted the legacy single-token file
(``~/.hermes/.anthropic_oauth.json``) and the env vars, so a pool-only login rendered as
disconnected in the desktop Accounts view while ``hermes auth list``/``status`` reported it
connected. These tests pin the precedence: PKCE file → credential pool → env var.
"""
import time

import hermes_cli.web_server_oauth as wso


def _no_pkce_file(monkeypatch):
    monkeypatch.setattr(
        "agent.anthropic_credentials.read_hermes_oauth_credentials", lambda: None, raising=False
    )


def _pool(monkeypatch, entries):
    monkeypatch.setattr(
        "hermes_cli.auth.read_credential_pool", lambda provider_id=None: entries, raising=False
    )


def test_pooled_oauth_credential_reads_as_connected(monkeypatch):
    _no_pkce_file(monkeypatch)
    _pool(monkeypatch, [{
        "id": "8ba8b2",
        "label": "claude-oauth",
        "auth_type": "oauth",
        "access_token": "sk-ant-oat01-secret-tail",
        "refresh_token": "sk-ant-ort01-refresh",
        "expires_at_ms": 1789558346831,
    }])

    status = wso._anthropic_oauth_status()

    assert status["logged_in"] is True
    assert status["source"] == "credential_pool"
    assert "claude-oauth" in status["source_label"]
    assert status["has_refresh_token"] is True
    # Never the whole token — the card shows a tail only.
    assert "sk-ant-oat01-secret-tail" not in status["token_preview"]


def test_expiry_is_reported_in_milliseconds_for_the_card(monkeypatch):
    """The card does ``new Date(expires_at)``: seconds would render as 1970 -> "expired"."""
    _no_pkce_file(monkeypatch)
    expires_at_ms = int((time.time() + 3600) * 1000)
    _pool(monkeypatch, [{"label": "x", "access_token": "tok", "expires_at_ms": expires_at_ms}])

    assert wso._anthropic_oauth_status()["expires_at"] == expires_at_ms


def test_claude_code_pool_row_is_not_the_anthropic_account(monkeypatch):
    """Claude Code has its own card; counting its mirrored pool row would shadow an env key."""
    _no_pkce_file(monkeypatch)
    _pool(monkeypatch, [{"source": "claude_code", "access_token": "cc-token", "refresh_token": "cc-refresh"}])
    monkeypatch.setattr(wso, "get_env_value", lambda *_a, **_k: None, raising=False)
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"):
        monkeypatch.delenv(var, raising=False)

    assert wso._anthropic_oauth_status()["logged_in"] is False


def test_expired_token_is_connected_only_while_it_can_refresh(monkeypatch):
    _no_pkce_file(monkeypatch)
    monkeypatch.setattr(wso, "get_env_value", lambda *_a, **_k: None, raising=False)
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    expired = {"label": "x", "access_token": "tok", "expires_at_ms": 1}

    _pool(monkeypatch, [{**expired, "refresh_token": "r"}])
    assert wso._anthropic_oauth_status()["logged_in"] is True

    _pool(monkeypatch, [expired])
    assert wso._anthropic_oauth_status()["logged_in"] is False


def test_entry_without_a_token_does_not_count_as_connected(monkeypatch):
    """A placeholder/exhausted pool row must not fake a login."""
    _no_pkce_file(monkeypatch)
    _pool(monkeypatch, [{"label": "empty", "auth_type": "oauth"}])
    monkeypatch.setattr(wso, "get_env_value", lambda *_a, **_k: None, raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_TOKEN", raising=False)
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

    assert wso._anthropic_oauth_status()["logged_in"] is False


def test_pkce_file_still_wins_over_the_pool(monkeypatch):
    """Precedence is unchanged: the Hermes-managed file is still the first source."""
    monkeypatch.setattr(
        "agent.anthropic_credentials.read_hermes_oauth_credentials",
        lambda: {"accessToken": "from-pkce-file"},
        raising=False,
    )
    _pool(monkeypatch, [{"label": "pooled", "access_token": "from-pool"}])

    assert wso._anthropic_oauth_status()["source"] == "hermes_pkce"


def test_pool_read_failure_falls_through_instead_of_raising(monkeypatch):
    """A broken/locked auth store must degrade to the env-var rung, never 500 the card."""
    _no_pkce_file(monkeypatch)

    def _boom(provider_id=None):
        raise OSError("auth.json unreadable")

    monkeypatch.setattr("hermes_cli.auth.read_credential_pool", _boom, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-key")

    status = wso._anthropic_oauth_status()

    assert status["logged_in"] is True
    assert status["source"] == "env_var"
