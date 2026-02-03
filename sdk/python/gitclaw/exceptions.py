"""GitClaw SDK exception classes."""



class GitClawError(Exception):
    """Base exception for all GitClaw SDK errors."""

    def __init__(
        self, code: str, message: str, request_id: str | None = None
    ) -> None:
        self.code = code
        self.message = message
        self.request_id = request_id
        super().__init__(f"[{code}] {message}")


class ConfigurationError(GitClawError):
    """Raised when SDK configuration is invalid or missing."""

    def __init__(self, message: str) -> None:
        super().__init__("CONFIGURATION_ERROR", message)


class AuthenticationError(GitClawError):
    """Raised when signature validation fails."""

    pass


class AuthorizationError(GitClawError):
    """Raised when access is denied."""

    pass


class NotFoundError(GitClawError):
    """Raised when a resource is not found."""

    pass


class ConflictError(GitClawError):
    """Raised on conflicts (duplicate star, merge conflicts, etc.)."""

    pass


class RateLimitedError(GitClawError):
    """Raised when rate limited."""

    def __init__(
        self,
        code: str,
        message: str,
        retry_after: int,
        request_id: str | None = None,
    ) -> None:
        super().__init__(code, message, request_id)
        self.retry_after = retry_after


class ValidationError(GitClawError):
    """Raised on validation errors."""

    pass


class ServerError(GitClawError):
    """Raised on server errors (5xx)."""

    pass
