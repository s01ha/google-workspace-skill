"""Tests for resolve_auth_provider factory and _validate_server_url."""

import pytest
from unittest.mock import patch, MagicMock

from gws.auth.provider import _validate_server_url, resolve_auth_provider
from gws.config import Config
from gws.exceptions import AuthError


class TestValidateServerUrl:

    def test_https_url_passes(self):
        _validate_server_url("https://relay.example.com")

    def test_http_localhost_passes(self):
        _validate_server_url("http://localhost:8080")

    def test_http_127_passes(self):
        _validate_server_url("http://127.0.0.1:3000")

    def test_http_ipv6_localhost_passes(self):
        _validate_server_url("http://[::1]:8080")

    def test_http_remote_raises(self):
        with pytest.raises(AuthError, match="Insecure server URL"):
            _validate_server_url("http://relay.example.com")

    def test_invalid_scheme_raises(self):
        with pytest.raises(AuthError, match="Invalid server URL scheme"):
            _validate_server_url("ftp://example.com")


class TestResolveAuthProvider:

    def _make_config(self, mode="local", server_url=None):
        """Create a Config with the given mode and server_url."""
        config = Config()
        config.mode = mode
        config.server_url = server_url
        return config

    def test_local_mode_returns_local_provider(self):
        config = self._make_config(mode="local")

        with patch("gws.auth.oauth.LocalAuthProvider") as mock_local, \
             patch.object(Config, "resolve_account", return_value=None), \
             patch.object(Config, "load_effective_config", return_value=config):
            mock_local.return_value = MagicMock()
            provider = resolve_auth_provider(config=config)
            mock_local.assert_called_once()
            assert provider is mock_local.return_value

    def test_server_mode_returns_server_provider(self):
        config = self._make_config(mode="server", server_url="https://relay.example.com")

        with patch("gws.auth.server.ServerAuthProvider") as mock_server, \
             patch.object(Config, "resolve_account", return_value=None), \
             patch.object(Config, "load_effective_config", return_value=config):
            mock_server.return_value = MagicMock()
            provider = resolve_auth_provider(config=config)
            mock_server.assert_called_once()
            assert provider is mock_server.return_value

    def test_env_var_overrides_server_url(self):
        config = self._make_config(mode="server", server_url="https://default.example.com")

        with patch("gws.auth.server.ServerAuthProvider") as mock_server, \
             patch.object(Config, "resolve_account", return_value=None), \
             patch.object(Config, "load_effective_config", return_value=config), \
             patch.dict("os.environ", {"GWS_SERVER_URL": "https://override.example.com"}):
            mock_server.return_value = MagicMock()
            resolve_auth_provider(config=config)
            call_kwargs = mock_server.call_args
            assert "override.example.com" in str(call_kwargs)

    def test_server_mode_without_url_returns_local(self):
        """Server mode without a server_url falls back to local."""
        config = self._make_config(mode="server", server_url=None)

        with patch("gws.auth.oauth.LocalAuthProvider") as mock_local, \
             patch.object(Config, "resolve_account", return_value=None), \
             patch.object(Config, "load_effective_config", return_value=config), \
             patch.dict("os.environ", {}, clear=False):
            # Ensure GWS_SERVER_URL is not set
            import os
            os.environ.pop("GWS_SERVER_URL", None)
            mock_local.return_value = MagicMock()
            provider = resolve_auth_provider(config=config)
            mock_local.assert_called_once()
            assert provider is mock_local.return_value

    def test_account_with_server_mode_override(self):
        """Per-account mode override to server should return ServerAuthProvider."""
        base_config = self._make_config(mode="local")
        effective_config = self._make_config(mode="server", server_url="https://account-relay.example.com")

        with patch("gws.auth.server.ServerAuthProvider") as mock_server, \
             patch.object(Config, "resolve_account", return_value="work"), \
             patch.object(Config, "load_effective_config", return_value=effective_config):
            mock_server.return_value = MagicMock()
            resolve_auth_provider(account="work", config=base_config)
            mock_server.assert_called_once()
            call_kwargs = mock_server.call_args
            assert "account-relay.example.com" in str(call_kwargs)


def test_local_logout_revokes_upstream_best_effort(tmp_path, monkeypatch):
    """Logging out locally should best-effort revoke the Google token, then
    still delete the local token file."""
    monkeypatch.setenv("GWS_ENCRYPTION", "none")
    monkeypatch.setattr(Config, "BASE_DIR", tmp_path)
    monkeypatch.setattr(Config, "CONFIG_PATH", tmp_path / "gws_config.json")

    from gws.auth.oauth import LocalAuthProvider
    from gws.crypto import save_encrypted

    provider = LocalAuthProvider(config=Config.load(), account=None)
    save_encrypted(provider.TOKEN_PATH, {"refresh_token": "RT", "token": "AT"}, None)

    calls = []

    class _Resp:
        status_code = 200

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return _Resp()

    monkeypatch.setattr("httpx.post", fake_post)

    assert provider.delete_token() is True
    assert not provider.TOKEN_PATH.exists()  # local file still removed
    assert calls, "expected an upstream revoke call"
    assert "oauth2.googleapis.com/revoke" in calls[0][0]
    assert calls[0][1]["data"]["token"] == "RT"
