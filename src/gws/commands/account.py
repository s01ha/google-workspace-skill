"""Account command group for gws-cli (multi-account management)."""

import typer
from typing import Annotated, Any, Optional

from gws.auth.provider import resolve_auth_provider
from gws.config import Config
from gws.output import output_json, output_success, output_error
from gws.exceptions import ExitCode, AuthError


app = typer.Typer(help="Multi-account management.")


@app.command("add")
def account_add(
    name: Annotated[str, typer.Argument(help="Account name (e.g., 'work', 'personal').")],
    display_name: Annotated[
        Optional[str],
        typer.Option("--name", help="Display name for From field in emails."),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Overwrite existing account."),
    ] = False,
    no_auth: Annotated[
        bool,
        typer.Option("--no-auth", help="Register account without triggering authentication."),
    ] = False,
) -> None:
    """Register and authenticate a new named account."""
    config = Config.load()

    if config.accounts and name in config.accounts.entries and not force:
        output_error(
            error_code="ACCOUNT_EXISTS",
            operation="account.add",
            message=f"Account '{name}' already exists. Use --force to overwrite.",
        )
        raise typer.Exit(ExitCode.INVALID_ARGS)

    try:
        Config.validate_account_name(name)
    except ValueError as e:
        output_error(
            error_code="INVALID_ARGS",
            operation="account.add",
            message=str(e),
        )
        raise typer.Exit(ExitCode.INVALID_ARGS)

    config.add_account(name, display_name=display_name or "")

    if no_auth:
        output_success(
            operation="account.add",
            message=f"Account '{name}' registered (authentication deferred).",
            account=name,
            is_default=config.accounts.default_account == name if config.accounts else False,
            hint="Run 'gws-cli auth -a {name}' or use any command with '-a {name}' to authenticate.".format(name=name),
        )
        return

    # Trigger authentication for the new account
    try:
        provider = resolve_auth_provider(account=name, config=config)
        credentials = provider.get_credentials()

        if credentials and credentials.valid:
            result: dict[str, Any] = {
                "operation": "account.add",
                "message": f"Account '{name}' added and authenticated.",
                "account": name,
                "is_default": config.accounts.default_account == name if config.accounts else False,
            }
            result["token_path"] = str(provider.TOKEN_PATH)
            output_success(**result)
        else:
            # Auth didn't produce valid credentials — keep account, warn user
            output_success(
                operation="account.add",
                message=f"Account '{name}' registered but authentication incomplete.",
                account=name,
                is_default=config.accounts.default_account == name if config.accounts else False,
                hint=f"Authenticate later with 'gws-cli auth -a {name}' or any command with '-a {name}'.",
            )
    except AuthError as e:
        # Auth failed — keep account registered, warn user
        output_success(
            operation="account.add",
            message=f"Account '{name}' registered (authentication skipped: {e}).",
            account=name,
            is_default=config.accounts.default_account == name if config.accounts else False,
            hint=f"Authenticate later with 'gws-cli auth -a {name}' or any command with '-a {name}'.",
        )


@app.command("update")
def account_update(
    name: Annotated[str, typer.Argument(help="Account name to update.")],
    display_name: Annotated[
        Optional[str],
        typer.Option("--name", help="Display name for From field in emails."),
    ] = None,
    email: Annotated[
        Optional[str],
        typer.Option("--email", help="Email address metadata."),
    ] = None,
) -> None:
    """Update account metadata (display name, email)."""
    config = Config.load()

    if display_name is None and email is None:
        output_error(
            error_code="INVALID_ARGS",
            operation="account.update",
            message="Provide at least one of --name or --email.",
        )
        raise typer.Exit(ExitCode.INVALID_ARGS)

    if config.update_account(name, display_name=display_name, email=email):
        updated = {}
        if display_name is not None:
            updated["name"] = display_name
        if email is not None:
            updated["email"] = email
        output_success(
            operation="account.update",
            message=f"Account '{name}' updated.",
            account=name,
            **updated,
        )
    else:
        output_error(
            error_code="NOT_FOUND",
            operation="account.update",
            message=f"Account '{name}' not found.",
        )
        raise typer.Exit(ExitCode.NOT_FOUND)


@app.command("remove")
def account_remove(
    name: Annotated[str, typer.Argument(help="Account name to remove.")],
) -> None:
    """Remove a named account and its credentials."""
    config = Config.load()

    if config.remove_account(name):
        output_success(
            operation="account.remove",
            message=f"Account '{name}' removed.",
            account=name,
        )
    else:
        output_error(
            error_code="NOT_FOUND",
            operation="account.remove",
            message=f"Account '{name}' not found.",
        )
        raise typer.Exit(ExitCode.NOT_FOUND)


@app.command("list")
def account_list() -> None:
    """List all configured accounts."""
    config = Config.load()
    accounts = config.list_accounts()

    output_json({
        "status": "success",
        "operation": "account.list",
        "accounts": accounts,
        "count": len(accounts),
        "default": config.accounts.default_account if config.accounts else None,
    })


@app.command("default")
def account_default(
    name: Annotated[str, typer.Argument(help="Account name to set as default.")],
) -> None:
    """Set the default account."""
    config = Config.load()

    if config.set_default_account(name):
        output_success(
            operation="account.default",
            message=f"Default account set to '{name}'.",
            account=name,
        )
    else:
        output_error(
            error_code="NOT_FOUND",
            operation="account.default",
            message=f"Account '{name}' not found.",
        )
        raise typer.Exit(ExitCode.NOT_FOUND)


@app.command("config")
def account_config_show(
    name: Annotated[str, typer.Argument(help="Account name.")],
) -> None:
    """Show effective configuration for an account."""
    config = Config.load()
    if not config.accounts or name not in config.accounts.entries:
        output_error(
            error_code="NOT_FOUND",
            operation="account.config",
            message=f"Account '{name}' not found.",
        )
        raise typer.Exit(ExitCode.NOT_FOUND)

    effective = config.load_effective_config(name)
    overrides = config.load_account_config(name)

    output_json({
        "status": "success",
        "operation": "account.config",
        "account": name,
        "effective_config": {
            "enabled_services": effective.enabled_services,
            "kroki_url": effective.kroki_url,
            "security_enabled": effective.security_enabled,
        },
        "has_overrides": bool(overrides),
        "overrides": overrides if overrides else None,
    })


@app.command("config-enable")
def account_config_enable(
    name: Annotated[str, typer.Argument(help="Account name.")],
    service: Annotated[str, typer.Argument(help="Service to enable for this account.")],
) -> None:
    """Enable a service for a specific account (override)."""
    config = Config.load()

    if not config.accounts or name not in config.accounts.entries:
        output_error(
            error_code="NOT_FOUND",
            operation="account.config.enable",
            message=f"Account '{name}' not found.",
        )
        raise typer.Exit(ExitCode.NOT_FOUND)

    if service not in Config.ALL_SERVICES:
        output_error(
            error_code="INVALID_SERVICE",
            operation="account.config.enable",
            message=f"Unknown service: {service}",
            details={"valid_services": Config.ALL_SERVICES},
        )
        raise typer.Exit(ExitCode.INVALID_ARGS)

    overrides = config.load_account_config(name)
    services = overrides.get("enabled_services", config.enabled_services.copy())
    if service not in services:
        services.append(service)
    overrides["enabled_services"] = services
    config.save_account_config(name, overrides)

    output_success(
        operation="account.config.enable",
        account=name,
        message=f"Service '{service}' enabled for account '{name}'.",
        enabled_services=services,
    )


@app.command("config-disable")
def account_config_disable(
    name: Annotated[str, typer.Argument(help="Account name.")],
    service: Annotated[str, typer.Argument(help="Service to disable for this account.")],
) -> None:
    """Disable a service for a specific account (override)."""
    config = Config.load()

    if not config.accounts or name not in config.accounts.entries:
        output_error(
            error_code="NOT_FOUND",
            operation="account.config.disable",
            message=f"Account '{name}' not found.",
        )
        raise typer.Exit(ExitCode.NOT_FOUND)

    if service not in Config.ALL_SERVICES:
        output_error(
            error_code="INVALID_SERVICE",
            operation="account.config.disable",
            message=f"Unknown service: {service}",
            details={"valid_services": Config.ALL_SERVICES},
        )
        raise typer.Exit(ExitCode.INVALID_ARGS)

    overrides = config.load_account_config(name)
    services = overrides.get("enabled_services", config.enabled_services.copy())
    if service in services:
        services.remove(service)
    overrides["enabled_services"] = services
    config.save_account_config(name, overrides)

    output_success(
        operation="account.config.disable",
        account=name,
        message=f"Service '{service}' disabled for account '{name}'.",
        enabled_services=services,
    )


@app.command("set-readonly")
def account_set_readonly(
    name: Annotated[str, typer.Argument(help="Account name.")],
) -> None:
    """Restrict an account to read-only operations."""
    config = Config.load()

    if not config.accounts or name not in config.accounts.entries:
        output_error(
            error_code="NOT_FOUND",
            operation="account.set-readonly",
            message=f"Account '{name}' not found.",
        )
        raise typer.Exit(ExitCode.NOT_FOUND)

    overrides = config.load_account_config(name)
    overrides["allowed_operations"] = Config.READ_ONLY_OPS
    overrides["read_only"] = True
    config.save_account_config(name, overrides)

    from gws.crypto import delete_encrypted
    token_path = config.get_account_dir(name) / "token.json"
    delete_encrypted(token_path)

    output_success(
        operation="account.set-readonly",
        account=name,
        message=f"Account '{name}' is now read-only.",
        allowed_operations=Config.READ_ONLY_OPS,
        note="Token cleared — next API call will re-authenticate with read-only scopes.",
    )


@app.command("unset-readonly")
def account_unset_readonly(
    name: Annotated[str, typer.Argument(help="Account name.")],
) -> None:
    """Remove read-only restriction from an account."""
    config = Config.load()

    if not config.accounts or name not in config.accounts.entries:
        output_error(
            error_code="NOT_FOUND",
            operation="account.unset-readonly",
            message=f"Account '{name}' not found.",
        )
        raise typer.Exit(ExitCode.NOT_FOUND)

    overrides = config.load_account_config(name)
    if "allowed_operations" in overrides:
        del overrides["allowed_operations"]
    if "read_only" in overrides:
        del overrides["read_only"]
    if overrides:
        config.save_account_config(name, overrides)
    else:
        config.clear_account_config(name)

    from gws.crypto import delete_encrypted
    token_path = config.get_account_dir(name) / "token.json"
    delete_encrypted(token_path)

    output_success(
        operation="account.unset-readonly",
        account=name,
        message=f"Account '{name}' is no longer read-only. All operations allowed.",
        note="Token cleared — next API call will re-authenticate with full scopes.",
    )


@app.command("config-reset")
def account_config_reset(
    name: Annotated[str, typer.Argument(help="Account name.")],
) -> None:
    """Remove all per-account overrides (inherit global config)."""
    config = Config.load()

    if not config.accounts or name not in config.accounts.entries:
        output_error(
            error_code="NOT_FOUND",
            operation="account.config.reset",
            message=f"Account '{name}' not found.",
        )
        raise typer.Exit(ExitCode.NOT_FOUND)

    config.clear_account_config(name)

    output_success(
        operation="account.config.reset",
        account=name,
        message=f"Per-account overrides cleared for '{name}'. Using global config.",
    )
