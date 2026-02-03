"""
GitClaw SDK logging utilities.

Provides configurable logging for HTTP requests/responses and signature operations.
Ensures no sensitive data (private keys, full signatures) is logged.

Design Reference: DR-4
Requirements: 16.1, 16.2, 16.3, 16.4
"""

import logging
import re
from typing import Any

# Create SDK-specific loggers
_sdk_logger = logging.getLogger("gitclaw")
_http_logger = logging.getLogger("gitclaw.http")
_signing_logger = logging.getLogger("gitclaw.signing")

# Patterns for sensitive data that should be masked
_SENSITIVE_PATTERNS = [
    # Private key patterns (PEM format)
    (re.compile(r"-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----", re.DOTALL), "[PRIVATE_KEY_REDACTED]"),
    # Base64 signatures (typically 64+ chars of base64)
    (re.compile(r'"signature"\s*:\s*"[A-Za-z0-9+/=]{64,}"'), '"signature": "[SIGNATURE_REDACTED]"'),
    # Raw signature bytes in hex
    (re.compile(r"signature['\"]?\s*[:=]\s*['\"]?[a-fA-F0-9]{128,}['\"]?"), "signature: [SIGNATURE_REDACTED]"),
    # Private key bytes (32 bytes = 64 hex chars or 44 base64 chars)
    (re.compile(r"private_key['\"]?\s*[:=]\s*['\"]?[a-fA-F0-9]{64}['\"]?"), "private_key: [REDACTED]"),
    (re.compile(r"private_key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9+/=]{43,44}['\"]?"), "private_key: [REDACTED]"),
    # Secret/token patterns
    (re.compile(r"(secret|token|password|api_key)['\"]?\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE), r"\1: [REDACTED]"),
]

# Maximum length for signature display (show first/last few chars)
_SIGNATURE_PREVIEW_LENGTH = 8


def configure_logging(
    level: int = logging.INFO,
    http_level: int | None = None,
    signing_level: int | None = None,
    handler: logging.Handler | None = None,
    format_string: str | None = None,
) -> None:
    """
    Configure GitClaw SDK logging.

    Args:
        level: Default log level for all SDK loggers (default: INFO)
        http_level: Log level for HTTP request/response logging (default: same as level)
        signing_level: Log level for signature operations (default: same as level)
        handler: Custom handler to use (default: StreamHandler to stderr)
        format_string: Custom format string (default: includes timestamp, level, logger name)

    Example:
        ```python
        import logging
        from gitclaw.logging import configure_logging

        # Enable debug logging for HTTP requests
        configure_logging(level=logging.INFO, http_level=logging.DEBUG)

        # Use custom handler
        file_handler = logging.FileHandler("gitclaw.log")
        configure_logging(handler=file_handler)
        ```

    Requirements: 16.1
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    formatter = logging.Formatter(format_string)

    if handler is None:
        handler = logging.StreamHandler()

    handler.setFormatter(formatter)

    # Configure main SDK logger
    _sdk_logger.setLevel(level)
    _sdk_logger.addHandler(handler)

    # Configure HTTP logger
    _http_logger.setLevel(http_level if http_level is not None else level)

    # Configure signing logger
    _signing_logger.setLevel(signing_level if signing_level is not None else level)


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Get a GitClaw SDK logger.

    Args:
        name: Logger name suffix (e.g., "http", "signing"). If None, returns main SDK logger.

    Returns:
        Logger instance

    Example:
        ```python
        from gitclaw.logging import get_logger

        logger = get_logger("http")
        logger.debug("Making request to /v1/repos")
        ```
    """
    if name is None:
        return _sdk_logger
    return logging.getLogger(f"gitclaw.{name}")


def mask_sensitive_data(text: str) -> str:
    """
    Mask sensitive data in a string.

    Replaces private keys, full signatures, and other sensitive patterns
    with redacted placeholders.

    Args:
        text: Text that may contain sensitive data

    Returns:
        Text with sensitive data masked

    Requirements: 16.4
    """
    result = text
    for pattern, replacement in _SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def truncate_signature(signature: str) -> str:
    """
    Truncate a signature for safe logging.

    Shows only the first and last few characters of a signature.

    Args:
        signature: Full signature string

    Returns:
        Truncated signature like "abc...xyz"

    Requirements: 16.4
    """
    if len(signature) <= _SIGNATURE_PREVIEW_LENGTH * 2:
        return "[SIGNATURE_REDACTED]"

    return f"{signature[:_SIGNATURE_PREVIEW_LENGTH]}...{signature[-_SIGNATURE_PREVIEW_LENGTH:]}"


def safe_log_dict(data: dict[str, Any], sensitive_keys: set[str] | None = None) -> dict[str, Any]:
    """
    Create a copy of a dictionary with sensitive values masked.

    Args:
        data: Dictionary that may contain sensitive values
        sensitive_keys: Set of keys to mask (default: signature, private_key, secret, token, password)

    Returns:
        Dictionary with sensitive values replaced with "[REDACTED]"

    Requirements: 16.4
    """
    if sensitive_keys is None:
        sensitive_keys = {"signature", "private_key", "secret", "token", "password", "api_key"}

    result: dict[str, Any] = {}
    for key, value in data.items():
        key_lower = key.lower()
        if key_lower in sensitive_keys or any(sk in key_lower for sk in sensitive_keys):
            if isinstance(value, str) and key_lower == "signature":
                result[key] = truncate_signature(value)
            else:
                result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = safe_log_dict(value, sensitive_keys)
        elif isinstance(value, list):
            result[key] = [
                safe_log_dict(item, sensitive_keys) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value

    return result


def log_http_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> None:
    """
    Log an HTTP request at DEBUG level with sensitive data masked.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Request URL
        headers: Request headers (optional)
        body: Request body (optional)

    Requirements: 16.2, 16.4
    """
    if not _http_logger.isEnabledFor(logging.DEBUG):
        return

    log_parts = [f"{method} {url}"]

    if headers:
        safe_headers = safe_log_dict(headers)
        log_parts.append(f"headers={safe_headers}")

    if body:
        safe_body = safe_log_dict(body)
        log_parts.append(f"body={safe_body}")

    _http_logger.debug(" | ".join(log_parts))


def log_http_response(
    status_code: int,
    url: str,
    body: dict[str, Any] | None = None,
    elapsed_ms: float | None = None,
) -> None:
    """
    Log an HTTP response at DEBUG level with sensitive data masked.

    Args:
        status_code: HTTP status code
        url: Request URL
        body: Response body (optional)
        elapsed_ms: Request duration in milliseconds (optional)

    Requirements: 16.2, 16.4
    """
    if not _http_logger.isEnabledFor(logging.DEBUG):
        return

    log_parts = [f"Response {status_code} from {url}"]

    if elapsed_ms is not None:
        log_parts.append(f"elapsed={elapsed_ms:.2f}ms")

    if body:
        safe_body = safe_log_dict(body)
        log_parts.append(f"body={safe_body}")

    _http_logger.debug(" | ".join(log_parts))


def log_signing_operation(
    operation: str,
    agent_id: str,
    action: str,
    nonce: str | None = None,
) -> None:
    """
    Log a signing operation at DEBUG level.

    Args:
        operation: Operation type (e.g., "sign_envelope", "verify_signature")
        agent_id: Agent ID
        action: Action being signed
        nonce: Nonce value (optional)

    Requirements: 16.3, 16.4
    """
    if not _signing_logger.isEnabledFor(logging.DEBUG):
        return

    log_parts = [f"{operation}: agent_id={agent_id}, action={action}"]

    if nonce:
        # Only show first 8 chars of nonce for debugging
        log_parts.append(f"nonce={nonce[:8]}...")

    _signing_logger.debug(" | ".join(log_parts))


# Export public API
__all__ = [
    "configure_logging",
    "get_logger",
    "mask_sensitive_data",
    "truncate_signature",
    "safe_log_dict",
    "log_http_request",
    "log_http_response",
    "log_signing_operation",
]
