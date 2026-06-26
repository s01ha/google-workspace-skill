"""Main CLI application for Google Workspace."""


import typer
from typing import Annotated, Optional

from gws import __version__
from gws.output import output_json

# Main app
app = typer.Typer(
    name="gws-cli",
    help="Google Workspace CLI - Unified management for Google services.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        output_json({"version": __version__})
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Google Workspace CLI - Manage Docs, Sheets, Slides, Drive, Gmail, Calendar, and Contacts."""
    pass


# Register command groups
from gws.commands import auth, account  # noqa: E402
from gws.commands import config as config_commands  # noqa: E402
from gws.commands import (  # noqa: E402
    drive, docs, sheets, slides, gmail, calendar, contacts, convert,
)

app.add_typer(auth.app, name="auth")
app.add_typer(account.app, name="account")
app.add_typer(config_commands.app, name="config")
app.add_typer(drive.app, name="drive")
app.add_typer(docs.app, name="docs")
app.add_typer(sheets.app, name="sheets")
app.add_typer(slides.app, name="slides")
app.add_typer(gmail.app, name="gmail")
app.add_typer(calendar.app, name="calendar")
app.add_typer(contacts.app, name="contacts")
app.add_typer(convert.app, name="convert")


if __name__ == "__main__":
    app()
