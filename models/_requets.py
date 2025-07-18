from typing import List, Optional
from pydantic import BaseModel, Field
from ._enums import SearchScope
class SearchRequest(BaseModel):
    """Request model for initiating a search."""
    usernames: List[str] = Field(
        ...,
        description="List of usernames to search for",
        min_items=1,
        example=["johndoe", "jane_doe"]
    )
    sites: Optional[List[str]] = Field(
        None,
        description="Specific sites to search (overrides scope if provided)"
    )
    scope: SearchScope = Field(
        SearchScope.TOP,
        description="Scope of the search operation"
    )
    max_sites: Optional[int] = Field(
        500,
        description="Maximum number of sites to search (for TOP scope)",
        ge=1
    )
    timeout: int = Field(
        10,
        description="Timeout in seconds for each request",
        ge=1
    )
    recursive: bool = Field(
        True,
        description="Enable recursive search for usernames found in profiles"
    )
    extract_info: bool = Field(
        True,
        description="Extract personal information from profiles"
    )
    permute: bool = Field(
        False,
        description="Generate username permutations"
    )
    retries: int = Field(
        1,
        description="Number of retries for failed requests",
        ge=0
    )
    tags: Optional[List[str]] = Field(
        None,
        description="Filter sites by tags (e.g., 'social', 'programming')"
    )
    countries: Optional[List[str]] = Field(
        None,
        description="Filter sites by country codes (e.g., 'us', 'gb')"
    )
