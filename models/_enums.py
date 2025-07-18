
from enum import Enum

class CheckStatus(str, Enum):
    """Status of a username check on a site."""
    CLAIMED = "Claimed"        # Username Detected
    AVAILABLE = "Available"    # Username Not Detected
    UNKNOWN = "Unknown"       # Error Occurred
    ILLEGAL = "Illegal"       # Username Not Allowed

class ReportFormat(str, Enum):
    """Supported report formats."""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    TXT = "txt"
    XMIND = "xmind"
    CSV = "csv"

class SearchScope(str, Enum):
    """Scope of the search operation."""
    TOP = "top"          # Top sites (default)
    ALL = "all"          # All sites
    SELECTED = "selected"  # Only selected sites
