from typing import Optional, Dict, Any
from ._error import ErrorResponse
def create_error_response(
    error: str,
    code: int,
    details: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None
) -> ErrorResponse:
    """Helper to create standardized error responses."""
    return ErrorResponse(
        error=error,
        code=code,
        details=details,
        request_id=request_id
    )