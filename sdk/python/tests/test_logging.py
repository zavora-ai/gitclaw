"""
Property-based tests for GitClaw SDK logging.

Feature: gitclaw-sdk
"""

import io
import logging

from hypothesis import given, settings
from hypothesis import strategies as st

from gitclaw.logging import (
    configure_logging,
    get_logger,
    log_http_request,
    log_http_response,
    log_signing_operation,
    mask_sensitive_data,
    safe_log_dict,
    truncate_signature,
)

# Strategies for generating test data
base64_signature_strategy = st.text(
    alphabet=st.sampled_from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
    min_size=64,
    max_size=128,
)

hex_string_strategy = st.text(
    alphabet=st.sampled_from("0123456789abcdefABCDEF"),
    min_size=64,
    max_size=128,
)

private_key_pem_strategy = st.just(
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIGhpcyBpcyBhIHRlc3QgcHJpdmF0ZSBrZXkgZGF0YQ==\n"
    "-----END PRIVATE KEY-----"
)

agent_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="-_"),
    min_size=1,
    max_size=50,
)

action_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_"),
    min_size=1,
    max_size=30,
)


@given(signature=base64_signature_strategy)
@settings(max_examples=100)
def test_property_no_full_signature_in_masked_output(signature: str) -> None:
    """
    Property 11: No sensitive data in logs

    For any log output produced by the SDK at any log level, the output
    SHALL NOT contain full signature values.

    Validates: Requirements 16.4 | Design: DR-4
    """
    # Create text containing a signature
    text_with_signature = f'{{"signature": "{signature}"}}'

    # Mask the sensitive data
    masked = mask_sensitive_data(text_with_signature)

    # The full signature should not appear in the masked output
    assert signature not in masked, (
        f"Full signature should be masked but found in output: {masked}"
    )


@given(
    signature=base64_signature_strategy,
    agent_id=agent_id_strategy,
    action=action_strategy,
)
@settings(max_examples=100)
def test_property_safe_log_dict_masks_signatures(
    signature: str, agent_id: str, action: str
) -> None:
    """
    Property 11: No sensitive data in logs

    For any dictionary containing signature values, safe_log_dict SHALL
    mask the signature values.

    Validates: Requirements 16.4 | Design: DR-4
    """
    data = {
        "agentId": agent_id,
        "action": action,
        "signature": signature,
        "nested": {
            "signature": signature,
        },
    }

    safe_data = safe_log_dict(data)

    # Full signature should not appear anywhere in the safe dict
    safe_str = str(safe_data)
    assert signature not in safe_str, (
        f"Full signature should be masked but found in safe_log_dict output"
    )

    # Signature key should still exist but be truncated or redacted
    assert "signature" in str(safe_data).lower()


@given(private_key_pem=private_key_pem_strategy)
@settings(max_examples=10)
def test_property_no_private_key_in_masked_output(private_key_pem: str) -> None:
    """
    Property 11: No sensitive data in logs

    For any log output produced by the SDK at any log level, the output
    SHALL NOT contain private key material.

    Validates: Requirements 16.4 | Design: DR-4
    """
    # Create text containing a private key
    text_with_key = f"Loading key: {private_key_pem}"

    # Mask the sensitive data
    masked = mask_sensitive_data(text_with_key)

    # The private key content should not appear in the masked output
    assert "BEGIN" not in masked or "PRIVATE KEY" not in masked, (
        f"Private key should be masked but found in output: {masked}"
    )
    assert "MC4CAQAwBQYDK2VwBCIEIGhpcyBpcyBhIHRlc3QgcHJpdmF0ZSBrZXkgZGF0YQ==" not in masked


@given(
    secret=st.text(min_size=10, max_size=50),
    token=st.text(min_size=10, max_size=50),
    password=st.text(min_size=10, max_size=50),
)
@settings(max_examples=100)
def test_property_safe_log_dict_masks_secrets(
    secret: str, token: str, password: str
) -> None:
    """
    Property 11: No sensitive data in logs

    For any dictionary containing secret/token/password values,
    safe_log_dict SHALL mask those values.

    Validates: Requirements 16.4 | Design: DR-4
    """
    data = {
        "secret": secret,
        "token": token,
        "password": password,
        "api_key": "some-api-key",
        "normal_field": "visible",
    }

    safe_data = safe_log_dict(data)

    # Sensitive values should be redacted
    assert safe_data["secret"] == "[REDACTED]"
    assert safe_data["token"] == "[REDACTED]"
    assert safe_data["password"] == "[REDACTED]"
    assert safe_data["api_key"] == "[REDACTED]"

    # Normal field should be visible
    assert safe_data["normal_field"] == "visible"


@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    url=st.text(
        min_size=5,
        max_size=100,
        alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="/-_"),
    ),
    signature=base64_signature_strategy,
    agent_id=agent_id_strategy,
)
@settings(max_examples=100)
def test_property_log_http_request_no_sensitive_data(
    method: str, url: str, signature: str, agent_id: str
) -> None:
    """
    Property 11: No sensitive data in logs

    For any HTTP request logged by the SDK, the log output SHALL NOT
    contain full signature values or private keys in the body section.

    Note: We only check the body section because the URL is user-provided
    data that we don't mask (and shouldn't - it's not sensitive).

    Validates: Requirements 16.4 | Design: DR-4
    """
    # Set up a string buffer to capture log output
    log_buffer = io.StringIO()
    handler = logging.StreamHandler(log_buffer)
    handler.setLevel(logging.DEBUG)

    # Configure logging to capture output
    http_logger = logging.getLogger("gitclaw.http")
    http_logger.setLevel(logging.DEBUG)
    http_logger.handlers = [handler]

    # Log a request with sensitive data
    body = {
        "agentId": agent_id,
        "signature": signature,
        "private_key": "secret-key-data",
    }

    log_http_request(method, url, body=body)

    # Get the log output
    log_output = log_buffer.getvalue()

    # Extract just the body section from the log output
    # The format is: "METHOD URL | body={...}"
    body_start = log_output.find("body=")
    if body_start != -1:
        body_section = log_output[body_start:]

        # Full signature should not appear in the body section
        assert signature not in body_section, (
            f"Full signature found in HTTP request body log: {body_section}"
        )

        # Private key should not appear in the body section
        assert "secret-key-data" not in body_section


@given(
    status_code=st.integers(min_value=200, max_value=599),
    url=st.text(
        min_size=5,
        max_size=100,
        alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="/-_"),
    ),
    signature=base64_signature_strategy,
)
@settings(max_examples=100)
def test_property_log_http_response_no_sensitive_data(
    status_code: int, url: str, signature: str
) -> None:
    """
    Property 11: No sensitive data in logs

    For any HTTP response logged by the SDK, the log output SHALL NOT
    contain full signature values in the body section.

    Note: We only check the body section because the URL is user-provided
    data that we don't mask (and shouldn't - it's not sensitive).

    Validates: Requirements 16.4 | Design: DR-4
    """
    # Set up a string buffer to capture log output
    log_buffer = io.StringIO()
    handler = logging.StreamHandler(log_buffer)
    handler.setLevel(logging.DEBUG)

    # Configure logging to capture output
    http_logger = logging.getLogger("gitclaw.http")
    http_logger.setLevel(logging.DEBUG)
    http_logger.handlers = [handler]

    # Log a response with sensitive data
    body = {
        "data": {"signature": signature},
        "meta": {"requestId": "req-123"},
    }

    log_http_response(status_code, url, body=body)

    # Get the log output
    log_output = log_buffer.getvalue()

    # Extract just the body section from the log output
    # The format is: "Response STATUS from URL | body={...}"
    body_start = log_output.find("body=")
    if body_start != -1:
        body_section = log_output[body_start:]

        # Full signature should not appear in the body section
        assert signature not in body_section, (
            f"Full signature found in HTTP response body log: {body_section}"
        )


@given(signature=base64_signature_strategy)
@settings(max_examples=100)
def test_truncate_signature_hides_middle(signature: str) -> None:
    """
    Test that truncate_signature only shows first and last few characters.

    Validates: Requirements 16.4 | Design: DR-4
    """
    truncated = truncate_signature(signature)

    # Should not contain the full signature
    assert signature not in truncated

    # Should be much shorter than original
    assert len(truncated) < len(signature)

    # Should contain ellipsis
    if len(signature) > 16:
        assert "..." in truncated


def test_configure_logging_sets_levels() -> None:
    """Test that configure_logging properly sets log levels."""
    # Configure with specific levels
    configure_logging(
        level=logging.WARNING,
        http_level=logging.DEBUG,
        signing_level=logging.ERROR,
    )

    # Verify levels are set
    sdk_logger = get_logger()
    http_logger = get_logger("http")
    signing_logger = get_logger("signing")

    assert sdk_logger.level == logging.WARNING
    assert http_logger.level == logging.DEBUG
    assert signing_logger.level == logging.ERROR


def test_get_logger_returns_correct_loggers() -> None:
    """Test that get_logger returns the correct logger instances."""
    # Main logger
    main_logger = get_logger()
    assert main_logger.name == "gitclaw"

    # HTTP logger
    http_logger = get_logger("http")
    assert http_logger.name == "gitclaw.http"

    # Signing logger
    signing_logger = get_logger("signing")
    assert signing_logger.name == "gitclaw.signing"


def test_mask_sensitive_data_preserves_non_sensitive() -> None:
    """Test that mask_sensitive_data preserves non-sensitive content."""
    text = "This is a normal log message with no secrets"
    masked = mask_sensitive_data(text)
    assert masked == text


def test_safe_log_dict_handles_nested_structures() -> None:
    """Test that safe_log_dict properly handles nested dictionaries and lists."""
    data = {
        "level1": {
            "level2": {
                "signature": "secret-sig",
                "normal": "visible",
            },
            "list_field": [
                {"signature": "list-sig", "data": "ok"},
                {"normal": "also-visible"},
            ],
        },
    }

    safe_data = safe_log_dict(data)

    # Nested signature should be masked
    assert "secret-sig" not in str(safe_data)
    assert "list-sig" not in str(safe_data)

    # Normal fields should be visible
    assert safe_data["level1"]["level2"]["normal"] == "visible"
    assert safe_data["level1"]["list_field"][1]["normal"] == "also-visible"
