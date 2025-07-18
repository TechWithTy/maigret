from typing import Optional
from pydantic import BaseModel, HttpUrl, Field
from ._requets import SearchRequest

class WebSearchRequest(SearchRequest):
    """Extended search request for web interface."""
    callback_url: Optional[HttpUrl] = Field(
        None,
        description="URL to receive search completion callback"
    )
    email_notification: Optional[str] = Field(
        None,
        description="Email address to notify when search is complete"
    )

class WebSearchResponse(BaseModel):
    """Response for web search initiation."""
    search_id: str
    status_url: HttpUrl
    estimated_time: Optional[int] = Field(
        None,
        description="Estimated time to complete in seconds"
    )
