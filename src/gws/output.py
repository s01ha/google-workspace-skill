"""JSON output formatting for GWS CLI."""

import json
import sys
from dataclasses import dataclass, field
from typing import Any

from prompt_security import output_external_content as _output_external_content
from prompt_security import load_config as load_security_config
from prompt_security import generate_markers
from prompt_security import detect_suspicious_content, Severity
from prompt_security import screen_content_semantic
from prompt_security import screen_content, screen_content_chunked

from gws.config import Config

# Session-scoped security markers — generated once at import time.
# For CLI tools the human controls the pipeline, so these are defense-in-depth.
_SESSION_START, _SESSION_END = generate_markers()


def _get_session_markers() -> tuple[str, str]:
    """Return the module-level session markers."""
    return _SESSION_START, _SESSION_END


def output_json(data: dict[str, Any]) -> None:
    """Output JSON to stdout."""
    print(json.dumps(data, indent=2, default=str))


def output_success(operation: str, **kwargs: Any) -> None:
    """Output success response."""
    response = {"status": "success", "operation": operation, **kwargs}
    output_json(response)


def output_error(
    error_code: str,
    operation: str,
    message: str,
    details: Any = None,
) -> None:
    """Output error response to stdout."""
    response: dict[str, Any] = {
        "status": "error",
        "error_code": error_code,
        "operation": operation,
        "message": message,
    }
    if details is not None:
        response["details"] = details
    output_json(response)


def output_external_content(
    operation: str,
    source_type: str,
    source_id: str,
    content_fields: dict[str, str],
    **kwargs: Any,
) -> None:
    """
    Output response with wrapped external content.

    Security is skipped if:
    - security_enabled=False in GWS config
    - The operation is in disabled_security_operations
    - The source is in the allowlist

    Args:
        operation: Operation name (e.g., "gmail.read")
        source_type: Type of source ("email", "document", "spreadsheet", "slide")
        source_id: Unique identifier (document ID, message ID, etc.)
        content_fields: Dict mapping field names to content to wrap
        **kwargs: Additional fields to include in response
    """
    from gws.context import get_active_account

    gws_config = Config.load()
    account = get_active_account()
    if account:
        gws_config = gws_config.load_effective_config(account)

    skip = (
        not gws_config.security_enabled
        or not gws_config.is_security_enabled_for_operation(operation)
        or gws_config.is_allowlisted(source_type, source_id)
    )

    security_config = None if skip else load_security_config()
    start, end = _get_session_markers()

    response = _output_external_content(
        operation=operation,
        source_type=source_type,
        source_id=source_id,
        content_fields=content_fields,
        start_marker=start,
        end_marker=end,
        config=security_config,
        skip_wrapping=skip,
        **kwargs,
    )
    output_json(response)


@dataclass
class ScreenVerdict:
    """Result of screening downloaded content."""

    allowed: bool
    is_binary: bool = False
    warnings: list[dict[str, Any]] = field(default_factory=list)
    advisory: str | None = None


_SECURITY_ADVISORY = (
    "This file was not screened for prompt injection (binary format). "
    "Before reading its contents, screen extracted text with: "
    "uvx prompt-security-utils <file>"
)


def _screen_text_content(
    text: str,
    security_config: Any,
) -> tuple[bool, list[dict[str, Any]]]:
    """Run the detection pipeline on text content. Returns (allowed, warnings)."""
    warnings: list[dict[str, Any]] = []
    blocked = False

    # Tier 1: Regex pattern detection
    if security_config.detection_enabled:
        custom_patterns = security_config.get_custom_patterns()
        detections = detect_suspicious_content(text, custom_patterns or None)
        for d in detections:
            warnings.append(d.to_dict())
            if d.severity == Severity.HIGH:
                blocked = True

    # Tier 2: Semantic similarity screening
    if security_config.semantic_enabled:
        semantic_result = screen_content_semantic(text, security_config)
        if semantic_result and semantic_result.injection_detected:
            warnings.append({"tier": "semantic", **semantic_result.to_dict()})
            blocked = True

    # Tier 3: LLM screening
    if security_config.llm_screen_enabled:
        if security_config.llm_screen_chunked:
            max_chunks = (
                security_config.llm_screen_max_chunks
                if security_config.llm_screen_max_chunks > 0
                else None
            )
            screen_result = screen_content_chunked(
                text, security_config, max_chunks=max_chunks
            )
        else:
            screen_result = screen_content(text, security_config)
        if screen_result and screen_result.injection_detected:
            warnings.append({"tier": "llm_screen", **screen_result.to_dict()})
            blocked = True

    return (not blocked, warnings)


def screen_download(
    raw_bytes: bytes,
    operation: str,
    source_type: str,
    source_id: str,
    force: bool = False,
) -> ScreenVerdict:
    """
    Screen downloaded content for prompt injection before writing to disk.

    Args:
        raw_bytes: Raw downloaded bytes (from BytesIO).
        operation: Operation name (e.g., "drive.download").
        source_type: Source type for allowlist lookup.
        source_id: Source ID for allowlist lookup.
        force: If True, skip all screening.

    Returns:
        ScreenVerdict with the decision and any warnings.
    """
    from gws.context import get_active_account

    if force:
        return ScreenVerdict(allowed=True)

    gws_config = Config.load()
    account = get_active_account()
    if account:
        gws_config = gws_config.load_effective_config(account)

    if not gws_config.security_enabled:
        return ScreenVerdict(allowed=True)

    if not gws_config.is_security_enabled_for_operation(operation):
        return ScreenVerdict(allowed=True)

    if gws_config.is_allowlisted(source_type, source_id):
        return ScreenVerdict(allowed=True)

    # Try to decode as text
    try:
        text = raw_bytes.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return ScreenVerdict(allowed=True, is_binary=True, advisory=_SECURITY_ADVISORY)

    if not text.strip():
        return ScreenVerdict(allowed=True)

    security_config = load_security_config()
    allowed, warnings = _screen_text_content(text, security_config)

    return ScreenVerdict(
        allowed=allowed,
        is_binary=False,
        warnings=warnings,
        advisory=_SECURITY_ADVISORY if not allowed else None,
    )


def read_json_stdin() -> dict[str, Any]:
    """Read JSON from stdin."""
    from gws.exceptions import ExitCode

    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError as e:
        output_error("INVALID_JSON", "stdin", f"Invalid JSON input: {e}")
        raise SystemExit(ExitCode.INVALID_ARGS)
