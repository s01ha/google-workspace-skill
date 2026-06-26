"""Config command group for gws-cli (services, allowlist, auth mode)."""


import typer
from typing import Annotated, Any, Optional

from gws.config import Config
from gws.output import output_json, output_success, output_error
from gws.exceptions import ExitCode


app = typer.Typer(help="Service configuration management.")


@app.callback(invoke_without_command=True)
def config_default(ctx: typer.Context) -> None:
    """Manage service configuration."""
    if ctx.invoked_subcommand is None:
        # Default: show current config
        config = Config.load()
        result: dict[str, Any] = {
            "status": "success",
            "operation": "config",
            "mode": config.mode,
            "enabled_services": config.enabled_services,
            "all_services": Config.ALL_SERVICES,
            "kroki_url": config.kroki_url,
            "security_enabled": config.security_enabled,
            "allowlisted_documents": config.allowlisted_documents,
            "allowlisted_emails": config.allowlisted_emails,
            "disabled_security_services": config.disabled_security_services,
            "disabled_security_operations": config.disabled_security_operations,
        }
        if config.server_url:
            result["server_url"] = config.server_url
        if config.is_multi_account:
            result["accounts"] = config.list_accounts()
            result["default_account"] = config.accounts.default_account if config.accounts else None
        output_json(result)


@app.command("list")
def config_list() -> None:
    """List all services and their status."""
    config = Config.load()
    services = {
        service: service in config.enabled_services
        for service in Config.ALL_SERVICES
    }
    output_json({
        "status": "success",
        "operation": "config.list",
        "services": services,
        "enabled_count": len(config.enabled_services),
        "total_count": len(Config.ALL_SERVICES),
    })


@app.command("enable")
def config_enable(
    service: Annotated[str, typer.Argument(help="Service name to enable.")],
) -> None:
    """Enable a service."""
    config = Config.load()

    if service not in Config.ALL_SERVICES:
        output_error(
            error_code="INVALID_SERVICE",
            operation="config.enable",
            message=f"Unknown service: {service}",
            details={"valid_services": Config.ALL_SERVICES},
        )
        raise typer.Exit(ExitCode.INVALID_ARGS)

    if config.enable_service(service):
        output_success(
            operation="config.enable",
            message=f"Service '{service}' enabled.",
            enabled_services=config.enabled_services,
        )
    else:
        output_json({
            "status": "success",
            "operation": "config.enable",
            "message": f"Service '{service}' was already enabled.",
            "enabled_services": config.enabled_services,
        })


@app.command("disable")
def config_disable(
    service: Annotated[str, typer.Argument(help="Service name to disable.")],
) -> None:
    """Disable a service."""
    config = Config.load()

    if service not in Config.ALL_SERVICES:
        output_error(
            error_code="INVALID_SERVICE",
            operation="config.disable",
            message=f"Unknown service: {service}",
            details={"valid_services": Config.ALL_SERVICES},
        )
        raise typer.Exit(ExitCode.INVALID_ARGS)

    if config.disable_service(service):
        output_success(
            operation="config.disable",
            message=f"Service '{service}' disabled.",
            enabled_services=config.enabled_services,
        )
    else:
        output_json({
            "status": "success",
            "operation": "config.disable",
            "message": f"Service '{service}' was already disabled.",
            "enabled_services": config.enabled_services,
        })


@app.command("reset")
def config_reset() -> None:
    """Reset configuration to defaults (all services enabled)."""
    config = Config.load()
    config.enabled_services = list(Config.ALL_SERVICES)
    config.kroki_url = Config.DEFAULT_KROKI_URL
    config.save()

    output_success(
        operation="config.reset",
        message="Configuration reset to defaults.",
        enabled_services=config.enabled_services,
        kroki_url=config.kroki_url,
    )


@app.command("set-kroki")
def config_set_kroki(
    url: Annotated[str, typer.Argument(help="Kroki server URL (e.g., http://localhost:8000).")],
) -> None:
    """Set the Kroki server URL for diagram rendering.

    Default is https://kroki.io (public server).
    Set a custom URL if you run a local Kroki instance.
    """
    config = Config.load()
    config.kroki_url = url.rstrip("/")
    config.save()

    output_success(
        operation="config.set-kroki",
        message=f"Kroki URL set to: {config.kroki_url}",
        kroki_url=config.kroki_url,
    )


@app.command("allowlist-add")
def config_allowlist_add(
    type_: Annotated[str, typer.Argument(help="Type: 'docs' or 'email'.", metavar="TYPE")],
    id_: Annotated[str, typer.Argument(help="Document ID or email message ID.", metavar="ID")],
) -> None:
    """Add an ID to the security allowlist.

    Allowlisted documents and emails skip security wrapping.

    Examples:
        gws-cli config allowlist-add docs 1abc2def3ghi
        gws-cli config allowlist-add email 18fd9a8b2c3d4e5f
    """
    config = Config.load()

    if type_ == "docs":
        if id_ not in config.allowlisted_documents:
            config.allowlisted_documents.append(id_)
            config.save()
            output_success(
                operation="config.allowlist-add",
                type="docs",
                id=id_,
                message=f"Document {id_} added to allowlist.",
                allowlisted_documents=config.allowlisted_documents,
            )
        else:
            output_json({
                "status": "success",
                "operation": "config.allowlist-add",
                "message": f"Document {id_} already in allowlist.",
            })
    elif type_ == "email":
        if id_ not in config.allowlisted_emails:
            config.allowlisted_emails.append(id_)
            config.save()
            output_success(
                operation="config.allowlist-add",
                type="email",
                id=id_,
                message=f"Email {id_} added to allowlist.",
                allowlisted_emails=config.allowlisted_emails,
            )
        else:
            output_json({
                "status": "success",
                "operation": "config.allowlist-add",
                "message": f"Email {id_} already in allowlist.",
            })
    else:
        output_error(
            error_code="INVALID_TYPE",
            operation="config.allowlist-add",
            message=f"Unknown type: {type_}. Use 'docs' or 'email'.",
        )
        raise typer.Exit(ExitCode.INVALID_ARGS)


@app.command("allowlist-remove")
def config_allowlist_remove(
    type_: Annotated[str, typer.Argument(help="Type: 'docs' or 'email'.", metavar="TYPE")],
    id_: Annotated[str, typer.Argument(help="Document ID or email message ID.", metavar="ID")],
) -> None:
    """Remove an ID from the security allowlist.

    Examples:
        gws-cli config allowlist-remove docs 1abc2def3ghi
        gws-cli config allowlist-remove email 18fd9a8b2c3d4e5f
    """
    config = Config.load()

    if type_ == "docs":
        if id_ in config.allowlisted_documents:
            config.allowlisted_documents.remove(id_)
            config.save()
            output_success(
                operation="config.allowlist-remove",
                type="docs",
                id=id_,
                message=f"Document {id_} removed from allowlist.",
                allowlisted_documents=config.allowlisted_documents,
            )
        else:
            output_json({
                "status": "success",
                "operation": "config.allowlist-remove",
                "message": f"Document {id_} was not in allowlist.",
            })
    elif type_ == "email":
        if id_ in config.allowlisted_emails:
            config.allowlisted_emails.remove(id_)
            config.save()
            output_success(
                operation="config.allowlist-remove",
                type="email",
                id=id_,
                message=f"Email {id_} removed from allowlist.",
                allowlisted_emails=config.allowlisted_emails,
            )
        else:
            output_json({
                "status": "success",
                "operation": "config.allowlist-remove",
                "message": f"Email {id_} was not in allowlist.",
            })
    else:
        output_error(
            error_code="INVALID_TYPE",
            operation="config.allowlist-remove",
            message=f"Unknown type: {type_}. Use 'docs' or 'email'.",
        )
        raise typer.Exit(ExitCode.INVALID_ARGS)


@app.command("allowlist-list")
def config_allowlist_list() -> None:
    """List all IDs in the security allowlist."""
    config = Config.load()
    output_success(
        operation="config.allowlist-list",
        allowlisted_documents=config.allowlisted_documents,
        allowlisted_emails=config.allowlisted_emails,
        total_count=len(config.allowlisted_documents) + len(config.allowlisted_emails),
    )


@app.command("set-mode")
def config_set_mode(
    mode: Annotated[str, typer.Argument(help="Auth mode: 'local' or 'server'.")],
    url: Annotated[
        Optional[str],
        typer.Option("--url", help="Server URL (required for server mode)."),
    ] = None,
    provider: Annotated[
        Optional[str],
        typer.Option("--provider", help="Relay provider name (e.g. 'google-workspace'). Required when server has multiple providers."),
    ] = None,
    account: Annotated[
        Optional[str],
        typer.Option("--account", "-a", help="Set mode for a specific account only."),
    ] = None,
) -> None:
    """Switch authentication mode between local and server.

    Local mode: uses client_secret.json for direct OAuth.
    Server mode: delegates auth to an oauth-token-relay server.

    When --account is specified, the mode is stored as a per-account override.
    Without --account, it sets the global default for all accounts.

    Examples:
        gws-cli config set-mode server --url https://auth.company.com
        gws-cli config set-mode server --url https://auth.company.com -a work --provider google-work
        gws-cli config set-mode local -a personal
    """
    if mode not in ("local", "server"):
        output_error(
            error_code="INVALID_ARGS",
            operation="config.set-mode",
            message=f"Invalid mode: {mode}. Use 'local' or 'server'.",
        )
        raise typer.Exit(ExitCode.INVALID_ARGS)

    if mode == "server" and not url:
        # Check if there's already a global server_url to inherit
        config = Config.load()
        if not config.server_url:
            output_error(
                error_code="INVALID_ARGS",
                operation="config.set-mode",
                message="Server mode requires --url (no global server_url to inherit).",
            )
            raise typer.Exit(ExitCode.INVALID_ARGS)

    config = Config.load()

    if account:
        # Auto-create account if it doesn't exist (convenience for setup)
        if account not in (config.accounts.entries if config.accounts else {}):
            try:
                Config.validate_account_name(account)
            except ValueError as e:
                output_error(
                    error_code="INVALID_ARGS",
                    operation="config.set-mode",
                    message=str(e),
                )
                raise typer.Exit(ExitCode.INVALID_ARGS)
            config.add_account(account)

        overrides = config.load_account_config(account)
        overrides["mode"] = mode
        if url:
            overrides["server_url"] = url.rstrip("/")
        elif mode == "local":
            overrides.pop("server_url", None)
        if provider is not None:
            overrides["server_provider"] = provider
        elif mode == "local":
            overrides.pop("server_provider", None)
        config.save_account_config(account, overrides)

        # Clear Google token so next API call re-authenticates via the new mode
        from gws.crypto import delete_encrypted
        token_path = config.get_account_dir(account) / "token.json"
        token_cleared = delete_encrypted(token_path)
    else:
        # Global config. Mirror the per-account branch: only overwrite
        # server_url/provider when explicitly provided, and clear them only
        # when switching to local. Switching to server without --url inherits
        # the existing global values rather than wiping them.
        config.mode = mode
        if url:
            config.server_url = url.rstrip("/")
        elif mode == "local":
            config.server_url = None
        if provider is not None:
            config.server_provider = provider
        elif mode == "local":
            config.server_provider = None
        config.save()
        token_cleared = False

    result: dict[str, Any] = {
        "operation": "config.set-mode",
        "message": f"Auth mode set to '{mode}'.",
        "mode": mode,
    }
    if account:
        result["account"] = account
        result["scope"] = "per-account"
        eff_url = overrides.get("server_url") or config.server_url
        eff_provider = overrides.get("server_provider") or config.server_provider
    else:
        result["scope"] = "global"
        eff_url = config.server_url
        eff_provider = config.server_provider
    # Surface the *effective* server URL/provider in server mode, including
    # values inherited from the global config when --url was omitted.
    if mode == "server" and eff_url:
        result["server_url"] = eff_url
    if mode == "server" and eff_provider:
        result["server_provider"] = eff_provider
    if token_cleared:
        result["note"] = "Token cleared — next API call will re-authenticate via the new mode."
    output_success(**result)
