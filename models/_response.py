
from enum import Enum
from typing import List, Dict, Optional, Set, Any, Union
from datetime import datetime
from pydantic import BaseModel, HttpUrl, Field
from typing_extensions import Literal
from ._enums import CheckStatus

class AccountInfo(BaseModel):
    """Detailed information about a user account on a specific site."""
    username: str
    url: HttpUrl
    site_name: str
    status: CheckStatus
    query_time: Optional[float] = Field(
        None,
        description="Time taken to query the site in seconds"
    )
    
    # Profile information
    user_id: Optional[str] = Field(
        None,
        description="User ID on the site (if available)"
    )
    display_name: Optional[str] = Field(
        None,
        description="User's display name on the site"
    )
    bio: Optional[str] = Field(
        None,
        description="User's bio or description"
    )
    location: Optional[str] = Field(
        None,
        description="User's location"
    )
    website: Optional[HttpUrl] = Field(
        None,
        description="User's website URL"
    )
    email: Optional[str] = Field(
        None,
        description="User's email address"
    )
    phone: Optional[str] = Field(
        None,
        description="User's phone number"
    )
    profile_image: Optional[HttpUrl] = Field(
        None,
        description="URL to the user's profile image"
    )
    cover_image: Optional[HttpUrl] = Field(
        None,
        description="URL to the user's cover image"
    )
    
    # Social metrics
    followers_count: Optional[int] = Field(
        None,
        description="Number of followers",
        ge=0
    )
    following_count: Optional[int] = Field(
        None,
        description="Number of accounts user is following",
        ge=0
    )
    posts_count: Optional[int] = Field(
        None,
        description="Number of posts or content items",
        ge=0
    )
    
    # Timestamps
    created_at: Optional[datetime] = Field(
        None,
        description="Account creation date"
    )
    last_seen: Optional[datetime] = Field(
        None,
        description="Last activity timestamp"
    )
    
    # Additional metadata
    is_verified: Optional[bool] = Field(
        None,
        description="Whether the account is verified"
    )
    is_private: Optional[bool] = Field(
        None,
        description="Whether the account is private"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags associated with the site"
    )
    raw_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw data from the site"
    )

class SearchResult(BaseModel):
    """Results for a single username search."""
    username: str
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the search was performed"
    )
    accounts: Dict[str, AccountInfo] = Field(
        default_factory=dict,
        description="Dictionary of site_name -> account info"
    )
    related_usernames: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Other usernames found during the search"
    )
    stats: Dict[str, int] = Field(
        default_factory=dict,
        description="Search statistics"
    )

class BatchSearchResult(BaseModel):
    """Results for a batch search operation."""
    search_id: str
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the batch search was initiated"
    )
    status: Literal["pending", "in_progress", "completed", "failed"] = "pending"
    progress: float = Field(
        0.0,
        description="Progress percentage (0-100)",
        ge=0.0,
        le=100.0
    )
    results: Dict[str, SearchResult] = Field(
        default_factory=dict,
        description="Search results by username"
    )
    errors: Dict[str, str] = Field(
        default_factory=dict,
        description="Any errors that occurred during the search"
    )
