from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    code: int
    details: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None

class ValidationError(ErrorResponse):
    """Validation error response."""
    error: str = "Validation Error"
    code: int = 400
    fields: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Field-specific validation errors"
    )
