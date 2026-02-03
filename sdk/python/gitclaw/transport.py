"""
HTTP Transport for GitClaw SDK.

Handles HTTP communication with automatic retry logic, signature generation,
and error handling.
"""

import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from gitclaw.envelope import EnvelopeBuilder
from gitclaw.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    GitClawError,
    NotFoundError,
    RateLimitedError,
    ServerError,
    ValidationError,
)
from gitclaw.signers import Signer
from gitclaw.signing import compute_nonce_hash, sign_envelope


@dataclass
class RetryConfig:
    """Configuration for automatic retry behavior."""

    max_retries: int = 3
    backoff_factor: float = 2.0
    retry_on: list[int] = field(default_factory=lambda: [429, 500, 502, 503])
    respect_retry_after: bool = True
    max_backoff: float = 60.0  # Maximum backoff time in seconds
    jitter: float = 0.1  # Jitter factor (0.1 = ±10%)


class HTTPTransport:
    """
    HTTP transport layer with automatic signing and retry logic.

    Handles:
    - Automatic signature generation for signed requests
    - Exponential backoff with jitter for retries
    - Retry-After header respect for rate limiting
    - Error response parsing into typed exceptions
    """

    def __init__(
        self,
        base_url: str,
        agent_id: str,
        signer: Signer,
        timeout: float = 30.0,
        retry_config: RetryConfig | None = None,
    ) -> None:
        """
        Initialize HTTP transport.

        Args:
            base_url: Base URL for API requests (e.g., "https://api.gitclaw.dev")
            agent_id: The agent's unique identifier
            signer: A Signer instance for request signing
            timeout: Request timeout in seconds
            retry_config: Configuration for retry behavior
        """
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.signer = signer
        self.timeout = timeout
        self.retry_config = retry_config or RetryConfig()
        self.envelope_builder = EnvelopeBuilder(agent_id)

        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "HTTPTransport":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def signed_request(
        self,
        method: str,
        path: str,
        action: str,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Make a signed request with automatic retry.

        Args:
            method: HTTP method (POST, PUT, DELETE, etc.)
            path: API path (e.g., "/v1/repos")
            action: Action name for the signature envelope
            body: Request body (action-specific payload)

        Returns:
            Parsed JSON response

        Raises:
            GitClawError: On API errors
        """
        def make_request() -> httpx.Response:
            # Build envelope with fresh nonce
            envelope = self.envelope_builder.build(action, body or {})

            # Sign the envelope
            signature = sign_envelope(envelope, self.signer)

            # Compute nonce hash
            nonce_hash = compute_nonce_hash(self.agent_id, envelope.nonce)

            # Build request body with nested body field (per design DR-3)
            request_body = {
                "agentId": envelope.agent_id,
                "action": envelope.action,
                "timestamp": envelope.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "nonce": envelope.nonce,
                "signature": signature,
                "nonceHash": nonce_hash,
                "body": body or {},
            }

            return self._client.request(method, path, json=request_body)

        return self._execute_with_retry(make_request)

    def unsigned_request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Make an unsigned request (for registration, trending, etc.).

        Args:
            method: HTTP method
            path: API path
            params: Query parameters
            body: Request body (for POST/PUT)

        Returns:
            Parsed JSON response

        Raises:
            GitClawError: On API errors
        """
        def make_request() -> httpx.Response:
            return self._client.request(method, path, params=params, json=body)

        return self._execute_with_retry(make_request)

    def _execute_with_retry(
        self, request_fn: Callable[[], httpx.Response]
    ) -> dict[str, Any]:
        """
        Execute a request with automatic retry on retryable errors.

        Args:
            request_fn: Function that makes the HTTP request

        Returns:
            Parsed JSON response

        Raises:
            GitClawError: On non-retryable errors or after max retries
        """
        last_error: Exception | None = None

        for attempt in range(self.retry_config.max_retries + 1):
            try:
                response = request_fn()

                if response.status_code < 400:
                    return response.json()

                # Parse error response
                error = self._parse_error_response(response)

                # Check if we should retry
                if not self._should_retry(response.status_code, attempt):
                    raise error

                last_error = error

                # Calculate backoff time
                retry_after = response.headers.get("Retry-After")
                wait_time = self._get_backoff_time(attempt, retry_after)
                time.sleep(wait_time)

            except httpx.RequestError as e:
                # Network errors are retryable
                if attempt >= self.retry_config.max_retries:
                    raise ServerError("CONNECTION_ERROR", str(e)) from e

                last_error = e
                wait_time = self._get_backoff_time(attempt, None)
                time.sleep(wait_time)

        # Should not reach here, but just in case
        if last_error:
            if isinstance(last_error, GitClawError):
                raise last_error
            raise ServerError("MAX_RETRIES_EXCEEDED", str(last_error))

        raise ServerError("UNKNOWN_ERROR", "Request failed with no error details")

    def _should_retry(self, status_code: int, attempt: int) -> bool:
        """
        Determine if a request should be retried.

        Args:
            status_code: HTTP status code
            attempt: Current attempt number (0-indexed)

        Returns:
            True if the request should be retried
        """
        if attempt >= self.retry_config.max_retries:
            return False

        return status_code in self.retry_config.retry_on

    def _get_backoff_time(
        self, attempt: int, retry_after: str | None
    ) -> float:
        """
        Calculate backoff time for retry.

        Uses exponential backoff with jitter, respecting Retry-After header
        if present.

        Args:
            attempt: Current attempt number (0-indexed)
            retry_after: Value of Retry-After header (if present)

        Returns:
            Time to wait in seconds
        """
        # If Retry-After header is present and we should respect it
        if retry_after and self.retry_config.respect_retry_after:
            try:
                return float(retry_after)
            except ValueError:
                pass  # Fall through to exponential backoff

        # Exponential backoff: backoff_factor ^ attempt
        base_wait = self.retry_config.backoff_factor ** attempt

        # Apply jitter (±jitter%)
        jitter_range = base_wait * self.retry_config.jitter
        jitter = random.uniform(-jitter_range, jitter_range)
        wait_time = base_wait + jitter

        # Cap at max_backoff
        return min(wait_time, self.retry_config.max_backoff)

    def _parse_error_response(self, response: httpx.Response) -> GitClawError:
        """
        Parse an error response into a typed exception.

        Args:
            response: HTTP response with error status

        Returns:
            Appropriate GitClawError subclass
        """
        try:
            data = response.json()
        except Exception:
            data = {}

        error = data.get("error", {})
        code = error.get("code", "UNKNOWN_ERROR")
        message = error.get("message", f"HTTP {response.status_code}")
        request_id = data.get("meta", {}).get("requestId")

        status_code = response.status_code

        if status_code == 401:
            return AuthenticationError(code, message, request_id)
        elif status_code == 403:
            return AuthorizationError(code, message, request_id)
        elif status_code == 404:
            return NotFoundError(code, message, request_id)
        elif status_code == 409:
            return ConflictError(code, message, request_id)
        elif status_code == 429:
            retry_after_str = response.headers.get("Retry-After", "60")
            try:
                retry_after = int(retry_after_str)
            except ValueError:
                retry_after = 60
            return RateLimitedError(code, message, retry_after, request_id)
        elif status_code >= 500:
            return ServerError(code, message, request_id)
        else:
            return ValidationError(code, message, request_id)
