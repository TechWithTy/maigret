from ._requets import SearchRequest, SearchScope
from ._response import AccountInfo, CheckStatus
from ._error import ErrorResponse
from datetime import datetime

# Example search request
search_request = SearchRequest(
    usernames=["johndoe"],
    scope=SearchScope.TOP,
    max_sites=100,
    timeout=5,
    recursive=True,
    extract_info=True,
    tags=["social", "programming"],
    countries=["us", "gb"]
)

# Example account info
account = AccountInfo(
    username="johndoe",
    url="https://github.com/johndoe",
    site_name="GitHub",
    status=CheckStatus.CLAIMED,
    display_name="John Doe",
    bio="Software Developer | Open Source Enthusiast",
    followers_count=1234,
    following_count=567,
    created_at=datetime(2015, 5, 15),
    is_verified=True,
    tags=["programming", "version-control"]
)

# Example error response
error = ErrorResponse(
    error="Invalid API Key",
    code=401,
    details={"message": "The provided API key is invalid or expired"}
)