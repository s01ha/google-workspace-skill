"""Tests for account CLI commands."""

import json
import pytest
from unittest.mock import patch, MagicMock

from typer.testing import CliRunner

from gws.cli import app
from gws.config import Config


runner = CliRunner()


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Set up isolated config directory."""
    monkeypatch.setattr(Config, "BASE_DIR", tmp_path)
    monkeypatch.setattr(Config, "CONFIG_PATH", tmp_path / "gws_config.json")
    monkeypatch.delenv("GWS_ACCOUNT", raising=False)
    return tmp_path


class TestAccountAdd:
    """Tests for 'gws account add'."""

    def test_add_account_success(self, config_dir):
        """Adding an account creates directory and triggers auth."""
        mock_creds = MagicMock()
        mock_creds.valid = True
        mock_creds.to_json.return_value = "{}"

        with patch("gws.auth.oauth.AuthManager.get_credentials", return_value=mock_creds), \
             patch("gws.auth.oauth.AuthManager.CREDENTIALS_PATH", config_dir / "client_secret.json"):
            result = runner.invoke(app, ["account", "add", "work"])

        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["status"] == "success"
        assert output["account"] == "work"
        assert (config_dir / "accounts" / "work").exists()

    def test_add_duplicate_account_fails(self, config_dir):
        """Adding an existing account without --force fails."""
        config = Config()
        config.add_account("work")

        result = runner.invoke(app, ["account", "add", "work"])
        assert result.exit_code != 0
        output = json.loads(result.stdout)
        assert output["error_code"] == "ACCOUNT_EXISTS"

    def test_add_duplicate_with_force(self, config_dir):
        """Adding an existing account with --force overwrites."""
        config = Config()
        config.add_account("work")

        mock_creds = MagicMock()
        mock_creds.valid = True
        mock_creds.to_json.return_value = "{}"

        with patch("gws.auth.oauth.AuthManager.get_credentials", return_value=mock_creds), \
             patch("gws.auth.oauth.AuthManager.CREDENTIALS_PATH", config_dir / "client_secret.json"):
            result = runner.invoke(app, ["account", "add", "work", "--force"])

        assert result.exit_code == 0


class TestAccountRemove:
    """Tests for 'gws account remove'."""

    def test_remove_existing_account(self, config_dir):
        config = Config()
        config.add_account("work")

        result = runner.invoke(app, ["account", "remove", "work"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["status"] == "success"

    def test_remove_nonexistent_account(self, config_dir):
        result = runner.invoke(app, ["account", "remove", "nonexistent"])
        assert result.exit_code != 0
        output = json.loads(result.stdout)
        assert output["error_code"] == "NOT_FOUND"


class TestAccountList:
    """Tests for 'gws account list'."""

    def test_list_empty(self, config_dir):
        result = runner.invoke(app, ["account", "list"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["count"] == 0
        assert output["accounts"] == {}

    def test_list_with_accounts(self, config_dir):
        config = Config()
        config.add_account("work", email="work@example.com")
        config.add_account("personal", email="me@gmail.com")

        result = runner.invoke(app, ["account", "list"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["count"] == 2
        assert output["default"] == "work"
        assert output["accounts"]["work"]["is_default"] is True


class TestAccountDefault:
    """Tests for 'gws account default'."""

    def test_set_default(self, config_dir):
        config = Config()
        config.add_account("work")
        config.add_account("personal")

        result = runner.invoke(app, ["account", "default", "personal"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["account"] == "personal"

    def test_set_default_nonexistent(self, config_dir):
        result = runner.invoke(app, ["account", "default", "nonexistent"])
        assert result.exit_code != 0


class TestAccountConfig:
    """Tests for 'gws account config' commands."""

    def test_show_config(self, config_dir):
        config = Config()
        config.add_account("work")

        result = runner.invoke(app, ["account", "config", "work"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["account"] == "work"
        assert output["has_overrides"] is False

    def test_config_enable_service(self, config_dir):
        config = Config()
        config.add_account("work")

        result = runner.invoke(app, ["account", "config-enable", "work", "docs"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert "docs" in output["enabled_services"]

    def test_config_disable_service(self, config_dir):
        config = Config()
        config.add_account("work")

        result = runner.invoke(app, ["account", "config-disable", "work", "gmail"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert "gmail" not in output["enabled_services"]

    def test_config_reset(self, config_dir):
        config = Config()
        config.add_account("work")
        config.save_account_config("work", {"enabled_services": ["docs"]})

        result = runner.invoke(app, ["account", "config-reset", "work"])
        assert result.exit_code == 0

        # Verify overrides removed
        assert config.load_account_config("work") == {}

    def test_config_nonexistent_account(self, config_dir):
        result = runner.invoke(app, ["account", "config", "nonexistent"])
        assert result.exit_code != 0

    def test_config_enable_invalid_service(self, config_dir):
        config = Config()
        config.add_account("work")

        result = runner.invoke(app, ["account", "config-enable", "work", "invalid_svc"])
        assert result.exit_code != 0
        output = json.loads(result.stdout)
        assert output["error_code"] == "INVALID_SERVICE"


class TestAuthWithAccount:
    """Tests for auth commands with --account flag."""

    def test_auth_status_with_account(self, config_dir):
        config = Config()
        config.add_account("work")

        result = runner.invoke(app, ["auth", "status", "--account", "work"])
        # Will be auth error (no token), but should include account info
        output = json.loads(result.stdout)
        assert output["account"] == "work"

    def test_auth_logout_with_account(self, config_dir):
        config = Config()
        config.add_account("work")

        result = runner.invoke(app, ["auth", "logout", "--account", "work"])
        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["operation"] == "auth.logout"


class TestSetModeGlobal:
    """Tests for 'gws config set-mode' on the global config (H1)."""

    def test_set_mode_server_without_url_preserves_inherited_url(self, config_dir):
        """Switching to server mode without --url must inherit the existing
        global server_url/provider, not wipe them (H1 regression)."""
        config = Config()
        config.server_url = "https://relay.example.com"
        config.server_provider = "google-workspace"
        config.mode = "local"
        config.save()

        result = runner.invoke(app, ["config", "set-mode", "server"])
        assert result.exit_code == 0, result.stdout

        reloaded = Config.load()
        assert reloaded.mode == "server"
        # The inherited values must survive the mode switch.
        assert reloaded.server_url == "https://relay.example.com"
        assert reloaded.server_provider == "google-workspace"

    def test_set_mode_server_inherited_url_is_reported(self, config_dir):
        """The effective server_url should be visible in the output, not hidden
        just because --url was omitted."""
        config = Config()
        config.server_url = "https://relay.example.com"
        config.server_provider = "google-workspace"
        config.mode = "local"
        config.save()

        result = runner.invoke(app, ["config", "set-mode", "server"])
        output = json.loads(result.stdout)
        assert output["server_url"] == "https://relay.example.com"

    def test_set_mode_local_clears_server_url(self, config_dir):
        """Switching to local mode clears the global server_url (existing behavior)."""
        config = Config()
        config.server_url = "https://relay.example.com"
        config.server_provider = "google-workspace"
        config.mode = "server"
        config.save()

        result = runner.invoke(app, ["config", "set-mode", "local"])
        assert result.exit_code == 0, result.stdout

        reloaded = Config.load()
        assert reloaded.mode == "local"
        assert reloaded.server_url is None
        assert reloaded.server_provider is None

    def test_set_mode_server_with_explicit_url_overrides(self, config_dir):
        """Passing --url still updates the global server_url."""
        config = Config()
        config.server_url = "https://old.example.com"
        config.mode = "local"
        config.save()

        result = runner.invoke(
            app, ["config", "set-mode", "server", "--url", "https://new.example.com"]
        )
        assert result.exit_code == 0, result.stdout

        reloaded = Config.load()
        assert reloaded.mode == "server"
        assert reloaded.server_url == "https://new.example.com"


class TestModeVisibility:
    """UX: the active auth mode must be discoverable (the original complaint)."""

    def test_auth_status_includes_mode_local(self, config_dir):
        config = Config()
        config.add_account("work")
        config.save()

        result = runner.invoke(app, ["auth", "status", "--account", "work"])
        output = json.loads(result.stdout)
        assert output["mode"] == "local"

    def test_auth_status_server_mode_shows_url(self, config_dir):
        config = Config()
        config.add_account("work")
        config.save()
        config.save_account_config(
            "work",
            {"mode": "server", "server_url": "https://relay.example.com",
             "server_provider": "google-workspace"},
        )

        with patch(
            "gws.auth.server.ServerAuthProvider.check_credentials",
            return_value=(False, "no_token", None),
        ):
            result = runner.invoke(app, ["auth", "status", "--account", "work"])
        output = json.loads(result.stdout)
        assert output["mode"] == "server"
        assert output["server_url"] == "https://relay.example.com"
        assert output["provider"] == "google-workspace"

    def test_account_list_includes_per_account_mode(self, config_dir):
        config = Config()
        config.add_account("work")
        config.add_account("home")
        config.save()
        config.save_account_config(
            "work", {"mode": "server", "server_url": "https://relay.example.com"}
        )

        result = runner.invoke(app, ["account", "list"])
        output = json.loads(result.stdout)
        assert output["accounts"]["work"]["mode"] == "server"
        assert output["accounts"]["work"]["server_url"] == "https://relay.example.com"
        assert output["accounts"]["home"]["mode"] == "local"

    def test_auth_help_explains_bare_auth_logs_in(self, config_dir):
        result = runner.invoke(app, ["auth", "--help"])
        text = result.stdout.lower()
        assert "mode" in text and "log" in text


class TestAuthInvalidAccount:
    """M1: bad --account in the bare auth path must be a clean JSON error."""

    def test_auth_invalid_account_name_is_clean_error(self, config_dir):
        result = runner.invoke(app, ["auth", "--account", "bad name"])
        # No uncaught exception / traceback
        assert result.exception is None or isinstance(result.exception, SystemExit)
        output = json.loads(result.stdout)
        assert output["status"] == "error"
        assert result.exit_code != 0
