"""Tests for Gmail MIME construction and helpers."""

import base64
import email
import json
from unittest.mock import MagicMock, patch

import pytest

from gws.services.gmail import GmailService


# =============================================================================
# TEST FIXTURES AND HELPERS
# =============================================================================


@pytest.fixture
def gmail_service():
    """Create a GmailService with fully mocked auth and API."""
    mock_auth = MagicMock()
    mock_creds = MagicMock()
    mock_creds.valid = True
    mock_auth.get_credentials.return_value = mock_creds
    # Default: no display name configured
    mock_auth.config.get_account_display_name.return_value = ""
    mock_auth.account_name = None

    with patch("gws.services.base.resolve_auth_provider", return_value=mock_auth), \
         patch("gws.services.base.build") as mock_build:

        mock_gmail_api = MagicMock()

        def build_side_effect(service_name, version, credentials=None):
            if service_name == "gmail":
                return mock_gmail_api
            return MagicMock()

        mock_build.side_effect = build_side_effect

        service = GmailService()
        service._mock_gmail_api = mock_gmail_api

        yield service


def decode_raw_message(mock_api):
    """Extract and decode the raw MIME message from the send() call args."""
    send_call = mock_api.users().messages().send
    call_kwargs = send_call.call_args
    # The call is: .send(userId="me", body={"raw": raw_b64})
    raw_b64 = call_kwargs[1]["body"]["raw"] if call_kwargs[1] else call_kwargs[0][1]["raw"]
    raw_bytes = base64.urlsafe_b64decode(raw_b64)
    return email.message_from_bytes(raw_bytes)


# =============================================================================
# _unescape_text TESTS
# =============================================================================


class TestUnescapeText:
    """Tests for GmailService._unescape_text."""

    def test_unescape_exclamation(self, gmail_service):
        """Backslash-escaped exclamation marks should be unescaped."""
        assert gmail_service._unescape_text("Hello \\! World") == "Hello ! World"

    def test_unescape_no_change(self, gmail_service):
        """Text without escape sequences should pass through unchanged."""
        assert gmail_service._unescape_text("Normal text") == "Normal text"

    def test_unescape_multiple(self, gmail_service):
        """Multiple escaped exclamation marks should all be unescaped."""
        assert gmail_service._unescape_text("Multiple \\! excl \\!") == "Multiple ! excl !"

    def test_unescape_empty_string(self, gmail_service):
        """Empty string should return empty string."""
        assert gmail_service._unescape_text("") == ""

    def test_unescape_only_backslash_bang(self, gmail_service):
        """String that is just the escape sequence."""
        assert gmail_service._unescape_text("\\!") == "!"

    def test_unescape_preserves_other_backslashes(self, gmail_service):
        """Other backslash sequences should remain unchanged."""
        assert gmail_service._unescape_text("path\\nto\\tfile") == "path\\nto\\tfile"


# =============================================================================
# send_message MIME CONSTRUCTION TESTS
# =============================================================================


class TestSendMessageMime:
    """Tests for Gmail MIME message construction in send_message."""

    def _setup_send_mock(self, gmail_service):
        """Set up the mock chain for users().messages().send().execute()."""
        gmail_service._mock_gmail_api.users().messages().send().execute.return_value = {
            "id": "msg-123",
            "threadId": "thread-456",
        }

    def test_send_plain_text(self, gmail_service, capsys):
        """Plain text email should use text/plain content type."""
        self._setup_send_mock(gmail_service)

        gmail_service.send_message(
            to="recipient@example.com",
            subject="Test Subject",
            body="Hello, plain text!",
            html=False,
        )

        output = json.loads(capsys.readouterr().out)
        assert output["status"] == "success"
        assert output["operation"] == "gmail.send"
        assert output["message_id"] == "msg-123"
        assert output["to"] == "recipient@example.com"
        assert output["subject"] == "Test Subject"

    def test_send_html(self, gmail_service, capsys):
        """HTML email should use text/html content type."""
        self._setup_send_mock(gmail_service)

        gmail_service.send_message(
            to="recipient@example.com",
            subject="Test HTML",
            body="<h1>Hello</h1>",
            html=True,
        )

        output = json.loads(capsys.readouterr().out)
        assert output["status"] == "success"
        assert output["operation"] == "gmail.send"

    def test_send_with_cc_bcc(self, gmail_service, capsys):
        """CC and BCC headers should appear in the MIME message."""
        self._setup_send_mock(gmail_service)

        gmail_service.send_message(
            to="recipient@example.com",
            subject="Test CC/BCC",
            body="Body text",
            cc="cc@example.com",
            bcc="bcc@example.com",
        )

        output = json.loads(capsys.readouterr().out)
        assert output["status"] == "success"

        # Verify the raw MIME was built with CC and BCC by inspecting
        # the body dict passed to send()
        send_call = gmail_service._mock_gmail_api.users().messages().send
        assert send_call.called

        # Get the raw message from the call
        call_kwargs = send_call.call_args
        raw_b64 = call_kwargs.kwargs.get("body", call_kwargs[1].get("body", {})).get("raw", "")
        raw_bytes = base64.urlsafe_b64decode(raw_b64)
        mime_msg = email.message_from_bytes(raw_bytes)

        assert mime_msg["to"] == "recipient@example.com"
        assert mime_msg["cc"] == "cc@example.com"
        assert mime_msg["bcc"] == "bcc@example.com"
        assert mime_msg["subject"] == "Test CC/BCC"

    def test_send_plain_text_mime_type(self, gmail_service, capsys):
        """Verify the MIME content type is text/plain for non-HTML."""
        self._setup_send_mock(gmail_service)

        gmail_service.send_message(
            to="recipient@example.com",
            subject="Plain",
            body="Plain body",
            html=False,
        )

        capsys.readouterr()  # consume output

        send_call = gmail_service._mock_gmail_api.users().messages().send
        call_kwargs = send_call.call_args
        raw_b64 = call_kwargs.kwargs.get("body", call_kwargs[1].get("body", {})).get("raw", "")
        raw_bytes = base64.urlsafe_b64decode(raw_b64)
        mime_msg = email.message_from_bytes(raw_bytes)

        assert mime_msg.get_content_type() == "text/plain"

    def test_send_html_mime_type(self, gmail_service, capsys):
        """Verify the MIME content type is text/html for HTML email."""
        self._setup_send_mock(gmail_service)

        gmail_service.send_message(
            to="recipient@example.com",
            subject="HTML",
            body="<p>HTML body</p>",
            html=True,
        )

        capsys.readouterr()  # consume output

        send_call = gmail_service._mock_gmail_api.users().messages().send
        call_kwargs = send_call.call_args
        raw_b64 = call_kwargs.kwargs.get("body", call_kwargs[1].get("body", {})).get("raw", "")
        raw_bytes = base64.urlsafe_b64decode(raw_b64)
        mime_msg = email.message_from_bytes(raw_bytes)

        assert mime_msg.get_content_type() == "text/html"

    def test_send_unescape_subject_and_body(self, gmail_service, capsys):
        """Subject and body should have shell escapes removed."""
        self._setup_send_mock(gmail_service)

        gmail_service.send_message(
            to="recipient@example.com",
            subject="Hello \\! World",
            body="Wow \\! Content",
            html=False,
        )

        capsys.readouterr()  # consume output

        send_call = gmail_service._mock_gmail_api.users().messages().send
        call_kwargs = send_call.call_args
        raw_b64 = call_kwargs.kwargs.get("body", call_kwargs[1].get("body", {})).get("raw", "")
        raw_bytes = base64.urlsafe_b64decode(raw_b64)
        mime_msg = email.message_from_bytes(raw_bytes)

        assert mime_msg["subject"] == "Hello ! World"
        body_text = mime_msg.get_payload(decode=True).decode("utf-8")
        assert "Wow ! Content" in body_text

    def test_send_with_signature(self, gmail_service, capsys):
        """Signature should be appended to body with separator."""
        self._setup_send_mock(gmail_service)

        gmail_service.send_message(
            to="recipient@example.com",
            subject="Signed",
            body="Main body",
            signature="Best regards,\nJohn",
            html=False,
        )

        capsys.readouterr()  # consume output

        send_call = gmail_service._mock_gmail_api.users().messages().send
        call_kwargs = send_call.call_args
        raw_b64 = call_kwargs.kwargs.get("body", call_kwargs[1].get("body", {})).get("raw", "")
        raw_bytes = base64.urlsafe_b64decode(raw_b64)
        mime_msg = email.message_from_bytes(raw_bytes)

        body_text = mime_msg.get_payload(decode=True).decode("utf-8")
        assert "Main body" in body_text
        assert "--" in body_text
        assert "Best regards," in body_text

    def test_send_with_from_name(self, gmail_service, capsys):
        """From header should include display name when from_name is provided."""
        self._setup_send_mock(gmail_service)

        # Mock get_profile via execute to return an email address
        with patch.object(
            GmailService, "get_profile",
            return_value={"emailAddress": "sender@example.com"},
        ):
            gmail_service.send_message(
                to="recipient@example.com",
                subject="Named sender",
                body="Body",
                from_name="John Doe",
                html=False,
            )

        capsys.readouterr()  # consume output

        send_call = gmail_service._mock_gmail_api.users().messages().send
        call_kwargs = send_call.call_args
        raw_b64 = call_kwargs.kwargs.get("body", call_kwargs[1].get("body", {})).get("raw", "")
        raw_bytes = base64.urlsafe_b64decode(raw_b64)
        mime_msg = email.message_from_bytes(raw_bytes)

        from_header = mime_msg["from"]
        assert "John Doe" in from_header
        assert "sender@example.com" in from_header

    def test_send_api_called_with_raw_body(self, gmail_service, capsys):
        """Verify send() is called with userId='me' and body containing 'raw' key."""
        self._setup_send_mock(gmail_service)

        gmail_service.send_message(
            to="recipient@example.com",
            subject="Test",
            body="Body",
        )

        capsys.readouterr()

        send_call = gmail_service._mock_gmail_api.users().messages().send
        assert send_call.called
        call_kwargs = send_call.call_args
        # Check userId and body.raw are present
        assert call_kwargs.kwargs.get("userId") or call_kwargs[1].get("userId") == "me"
        body_arg = call_kwargs.kwargs.get("body") or call_kwargs[1].get("body")
        assert "raw" in body_arg


# =============================================================================
# get_profile BEST-EFFORT TESTS
# =============================================================================


class TestGetProfile:
    """Tests for get_profile best-effort behavior."""

    def test_profile_success(self, gmail_service):
        """Successful profile call returns profile data."""
        from gws.services.base import BaseService

        with patch.object(
            BaseService, "execute",
            return_value={"emailAddress": "test@example.com", "messagesTotal": 1000},
        ):
            result = gmail_service.get_profile()
            assert result["emailAddress"] == "test@example.com"
            assert result["messagesTotal"] == 1000

    def test_profile_error_returns_empty_dict(self, gmail_service):
        """API error in get_profile returns empty dict instead of raising."""
        from googleapiclient.errors import HttpError
        from gws.services.base import BaseService

        mock_response = MagicMock()
        mock_response.status = 403
        http_error = HttpError(mock_response, b"Forbidden")

        with patch.object(BaseService, "execute", side_effect=http_error):
            result = gmail_service.get_profile()
            assert result == {}

    def test_profile_500_error_returns_empty_dict(self, gmail_service):
        """Server error in get_profile also returns empty dict."""
        from googleapiclient.errors import HttpError
        from gws.services.base import BaseService

        mock_response = MagicMock()
        mock_response.status = 500
        http_error = HttpError(mock_response, b"Internal Server Error")

        with patch.object(BaseService, "execute", side_effect=http_error):
            result = gmail_service.get_profile()
            assert result == {}


# =============================================================================
# DRAFT HEADER CASE-INSENSITIVITY TESTS
# =============================================================================


class TestDraftHeaderCase:
    """Drafts built via MIMEText store lowercase header names ('to','cc',
    'subject'); reads must be case-insensitive or they come back empty."""

    def _lowercase_draft(self):
        return {
            "id": "draft-1",
            "message": {
                "id": "msg-1",
                "payload": {
                    "headers": [
                        {"name": "to", "value": "a@x.com"},
                        {"name": "cc", "value": "c@x.com"},
                        {"name": "subject", "value": "Hello there"},
                    ],
                    "body": {},
                },
            },
        }

    def test_get_draft_reads_lowercase_headers(self, gmail_service):
        gmail_service._mock_gmail_api.users().drafts().get().execute.return_value = (
            self._lowercase_draft()
        )
        with patch("gws.services.gmail.output_external_content") as mock_out:
            gmail_service.get_draft("draft-1")
        kwargs = mock_out.call_args.kwargs
        assert kwargs["to"] == "a@x.com"
        assert kwargs["cc"] == "c@x.com"
        assert kwargs["content_fields"]["subject"] == "Hello there"

    def test_update_draft_body_only_preserves_recipients(self, gmail_service):
        """Updating only the body must not wipe to/cc/subject (lowercase headers)."""
        gmail_service._mock_gmail_api.users().drafts().get().execute.return_value = (
            self._lowercase_draft()
        )
        gmail_service._mock_gmail_api.users().drafts().update().execute.return_value = {
            "id": "draft-1"
        }
        gmail_service.update_draft("draft-1", body="brand new body")

        update_call = gmail_service._mock_gmail_api.users().drafts().update
        raw_b64 = update_call.call_args.kwargs["body"]["message"]["raw"]
        mime = email.message_from_bytes(base64.urlsafe_b64decode(raw_b64))
        assert mime["to"] == "a@x.com"
        assert mime["subject"] == "Hello there"
        assert mime["cc"] == "c@x.com"


# =============================================================================
# REPLY CC/BCC + REPLY-ALL TESTS
# =============================================================================


class TestReplyRecipients:
    """reply must support --cc/--bcc and --all (reply-all), while still
    threading (In-Reply-To/References)."""

    def _setup(self, gmail_service, orig_headers):
        gmail_service._mock_gmail_api.users().messages().get().execute.return_value = {
            "id": "m1",
            "threadId": "t1",
            "payload": {
                "headers": [{"name": k, "value": v} for k, v in orig_headers.items()]
            },
        }
        gmail_service._mock_gmail_api.users().messages().send().execute.return_value = {
            "id": "r1",
            "threadId": "t1",
        }

    def test_reply_with_cc_and_bcc(self, gmail_service, capsys):
        self._setup(gmail_service, {
            "from": "alice@x.com", "subject": "Hi", "message-id": "<m1@x>",
        })
        gmail_service.reply_to_message("m1", "body", cc="c@x.com", bcc="b@x.com")
        capsys.readouterr()
        mime = decode_raw_message(gmail_service._mock_gmail_api)
        assert mime["to"] == "alice@x.com"
        assert mime["cc"] == "c@x.com"
        assert mime["bcc"] == "b@x.com"
        assert mime["In-Reply-To"] == "<m1@x>"  # still threads

    def test_reply_all_gathers_recipients_minus_self(self, gmail_service, capsys):
        with patch.object(GmailService, "get_profile",
                          return_value={"emailAddress": "me@x.com"}):
            self._setup(gmail_service, {
                "from": "alice@x.com",
                "to": "me@x.com, bob@x.com",
                "cc": "carol@x.com, me@x.com",
                "subject": "Hi", "message-id": "<m1@x>",
            })
            gmail_service.reply_to_message("m1", "body", reply_all=True)
        capsys.readouterr()
        mime = decode_raw_message(gmail_service._mock_gmail_api)
        to = mime["to"]
        assert "alice@x.com" in to and "bob@x.com" in to
        assert "me@x.com" not in to            # self excluded
        cc = mime["cc"] or ""
        assert "carol@x.com" in cc
        assert "me@x.com" not in cc            # self excluded from cc too

    def test_reply_all_unions_explicit_cc(self, gmail_service, capsys):
        with patch.object(GmailService, "get_profile",
                          return_value={"emailAddress": "me@x.com"}):
            self._setup(gmail_service, {
                "from": "alice@x.com", "cc": "carol@x.com",
                "subject": "Hi", "message-id": "<m1@x>",
            })
            gmail_service.reply_to_message("m1", "body", reply_all=True, cc="dan@x.com")
        capsys.readouterr()
        mime = decode_raw_message(gmail_service._mock_gmail_api)
        cc = mime["cc"] or ""
        assert "carol@x.com" in cc and "dan@x.com" in cc
