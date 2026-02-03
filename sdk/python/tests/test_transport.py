"""
Property-based tests for HTTP Transport retry behavior.

Feature: gitclaw-sdk
"""

from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from gitclaw.signers import Ed25519Signer
from gitclaw.transport import HTTPTransport, RetryConfig

# Test strategies
backoff_factor_strategy = st.floats(min_value=1.1, max_value=5.0)
attempt_strategy = st.integers(min_value=0, max_value=5)
retry_after_strategy = st.integers(min_value=1, max_value=120)


@given(
    backoff_factor=backoff_factor_strategy,
    attempt=attempt_strategy,
)
@settings(max_examples=100)
def test_exponential_backoff_timing(backoff_factor: float, attempt: int) -> None:
    """
    Property 5: Exponential backoff timing

    For any retry configuration with backoff_factor B and attempt number N,
    the wait time before attempt N SHALL be approximately B^N seconds (with jitter).

    Validates: Requirements 5.2 | Design: DR-4
    """
    signer, _ = Ed25519Signer.generate()
    config = RetryConfig(
        backoff_factor=backoff_factor,
        jitter=0.1,  # ±10% jitter
        max_backoff=1000.0,  # High max to not interfere with test
    )

    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id="test-agent",
        signer=signer,
        retry_config=config,
    )

    # Calculate expected base wait time
    expected_base = backoff_factor ** attempt

    # Get actual wait time (without Retry-After)
    actual = transport._get_backoff_time(attempt, None)

    # Should be within jitter range (±10%)
    min_expected = expected_base * 0.9
    max_expected = expected_base * 1.1

    # Also cap at max_backoff
    max_expected = min(max_expected, config.max_backoff)
    min_expected = min(min_expected, config.max_backoff)

    assert min_expected <= actual <= max_expected, (
        f"Backoff time {actual} not in expected range [{min_expected}, {max_expected}] "
        f"for attempt {attempt} with factor {backoff_factor}"
    )


@given(retry_after=retry_after_strategy)
@settings(max_examples=100)
def test_retry_after_header_respected(retry_after: int) -> None:
    """
    Property 6: Retry-After header respected

    For any 429 response with a Retry-After header value of T seconds,
    the SDK SHALL wait at least T seconds before retrying.

    Validates: Requirements 5.3 | Design: DR-4
    """
    signer, _ = Ed25519Signer.generate()
    config = RetryConfig(respect_retry_after=True)

    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id="test-agent",
        signer=signer,
        retry_config=config,
    )

    # Get backoff time with Retry-After header
    actual = transport._get_backoff_time(0, str(retry_after))

    # Should exactly match Retry-After value
    assert actual == float(retry_after), (
        f"Expected wait time {retry_after}, got {actual}"
    )


@given(
    status_code=st.sampled_from([400, 401, 403, 404, 409]),
    attempt=st.integers(min_value=0, max_value=2),
)
@settings(max_examples=100)
def test_no_retry_on_non_retryable_errors(status_code: int, attempt: int) -> None:
    """
    Property 7: No retry on non-retryable errors

    For any response with status code in {400, 401, 403, 404, 409}
    (client errors except 429), the SDK SHALL NOT retry the request.

    Validates: Requirements 5.5 | Design: DR-4
    """
    signer, _ = Ed25519Signer.generate()
    config = RetryConfig(
        max_retries=3,
        retry_on=[429, 500, 502, 503],  # Default retryable codes
    )

    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id="test-agent",
        signer=signer,
        retry_config=config,
    )

    # Should not retry on these status codes
    should_retry = transport._should_retry(status_code, attempt)

    assert not should_retry, (
        f"Should not retry on status code {status_code}"
    )


@given(
    status_code=st.sampled_from([429, 500, 502, 503]),
    attempt=st.integers(min_value=0, max_value=2),
)
@settings(max_examples=100)
def test_retry_on_retryable_errors(status_code: int, attempt: int) -> None:
    """
    Test that retryable status codes trigger retry (when under max_retries).

    Validates: Requirements 5.2 | Design: DR-4
    """
    signer, _ = Ed25519Signer.generate()
    config = RetryConfig(
        max_retries=3,
        retry_on=[429, 500, 502, 503],
    )

    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id="test-agent",
        signer=signer,
        retry_config=config,
    )

    # Should retry on these status codes (when under max_retries)
    should_retry = transport._should_retry(status_code, attempt)

    assert should_retry, (
        f"Should retry on status code {status_code} at attempt {attempt}"
    )


def test_retry_generates_new_nonces() -> None:
    """
    Property 4: Retry generates new nonces

    For any request that is retried due to a retryable error, each retry
    attempt SHALL use a different nonce than all previous attempts.

    Validates: Requirements 4.4, 5.4 | Design: DR-4
    """
    signer, _ = Ed25519Signer.generate()
    config = RetryConfig(max_retries=3)

    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id="test-agent",
        signer=signer,
        retry_config=config,
    )

    # Track nonces across multiple envelope builds
    nonces: set[str] = set()

    # Simulate multiple retry attempts by building envelopes
    for _ in range(10):
        envelope = transport.envelope_builder.build("test_action", {"key": "value"})
        nonce = envelope.nonce

        assert nonce not in nonces, f"Nonce {nonce} was reused"
        nonces.add(nonce)


def test_max_retries_exceeded() -> None:
    """Test that retries stop after max_retries is reached."""
    signer, _ = Ed25519Signer.generate()
    config = RetryConfig(max_retries=2)

    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id="test-agent",
        signer=signer,
        retry_config=config,
    )

    # At max_retries, should not retry
    assert not transport._should_retry(500, 2), "Should not retry at max_retries"
    assert not transport._should_retry(500, 3), "Should not retry beyond max_retries"

    # Before max_retries, should retry
    assert transport._should_retry(500, 0), "Should retry at attempt 0"
    assert transport._should_retry(500, 1), "Should retry at attempt 1"


def test_backoff_respects_max_backoff() -> None:
    """Test that backoff time is capped at max_backoff."""
    signer, _ = Ed25519Signer.generate()
    config = RetryConfig(
        backoff_factor=10.0,  # Large factor
        max_backoff=5.0,  # Small max
        jitter=0.0,  # No jitter for predictable test
    )

    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id="test-agent",
        signer=signer,
        retry_config=config,
    )

    # At attempt 3, base would be 10^3 = 1000, but should be capped at 5
    actual = transport._get_backoff_time(3, None)

    assert actual == 5.0, f"Expected max_backoff 5.0, got {actual}"


def test_error_response_parsing() -> None:
    """Test that error responses are parsed into correct exception types."""
    signer, _ = Ed25519Signer.generate()
    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id="test-agent",
        signer=signer,
    )

    # Create mock responses for different status codes
    test_cases = [
        (401, "AuthenticationError"),
        (403, "AuthorizationError"),
        (404, "NotFoundError"),
        (409, "ConflictError"),
        (429, "RateLimitedError"),
        (500, "ServerError"),
        (400, "ValidationError"),
    ]

    for status_code, expected_type in test_cases:
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = {
            "error": {"code": "TEST_ERROR", "message": "Test message"},
            "meta": {"requestId": "req-123"},
        }
        mock_response.headers = {"Retry-After": "60"}

        error = transport._parse_error_response(mock_response)

        assert type(error).__name__ == expected_type, (
            f"Expected {expected_type} for status {status_code}, got {type(error).__name__}"
        )
        assert error.code == "TEST_ERROR"
        assert error.message == "Test message"
        assert error.request_id == "req-123"


# Status code to exception type mapping for property test
STATUS_CODE_TO_EXCEPTION = {
    401: "AuthenticationError",
    403: "AuthorizationError",
    404: "NotFoundError",
    409: "ConflictError",
    429: "RateLimitedError",
    500: "ServerError",
    502: "ServerError",
    503: "ServerError",
    400: "ValidationError",
    422: "ValidationError",
}


@given(
    status_code=st.sampled_from([401, 403, 404, 409, 429, 500, 502, 503, 400, 422]),
    error_code=st.text(min_size=1, max_size=50, alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"),
        whitelist_characters="_"
    )),
    error_message=st.text(min_size=1, max_size=200),
    request_id=st.text(min_size=1, max_size=50, alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"),
        whitelist_characters="-"
    )),
    retry_after=st.integers(min_value=1, max_value=3600),
)
@settings(max_examples=100)
def test_property_error_response_parsing(
    status_code: int,
    error_code: str,
    error_message: str,
    request_id: str,
    retry_after: int,
) -> None:
    """
    Property 15: Error response parsing

    For any error response from the API, the SDK SHALL parse it into a typed
    exception containing:
    - error code
    - error message
    - request_id

    And for rate limit errors, additionally:
    - retry_after seconds

    Validates: Requirements 13.2, 13.3 | Design: DR-8
    """
    signer, _ = Ed25519Signer.generate()
    transport = HTTPTransport(
        base_url="https://api.gitclaw.dev",
        agent_id="test-agent",
        signer=signer,
    )

    # Create mock response
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = {
        "error": {"code": error_code, "message": error_message},
        "meta": {"requestId": request_id},
    }
    mock_response.headers = {"Retry-After": str(retry_after)}

    # Parse the error response
    error = transport._parse_error_response(mock_response)

    # Verify exception type matches status code
    expected_type = STATUS_CODE_TO_EXCEPTION[status_code]
    assert type(error).__name__ == expected_type, (
        f"Expected {expected_type} for status {status_code}, got {type(error).__name__}"
    )

    # Verify error code is extracted
    assert error.code == error_code, (
        f"Expected error code '{error_code}', got '{error.code}'"
    )

    # Verify error message is extracted
    assert error.message == error_message, (
        f"Expected error message '{error_message}', got '{error.message}'"
    )

    # Verify request_id is extracted
    assert error.request_id == request_id, (
        f"Expected request_id '{request_id}', got '{error.request_id}'"
    )

    # For rate limit errors, verify retry_after is extracted
    if status_code == 429:
        from gitclaw.exceptions import RateLimitedError
        assert isinstance(error, RateLimitedError)
        assert error.retry_after == retry_after, (
            f"Expected retry_after {retry_after}, got {error.retry_after}"
        )
