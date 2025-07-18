from typing import List, Dict
from pydantic import BaseModel, Field
from datetime import datetime
from ._enums import ReportFormat

class ReportRequest(BaseModel):
    """Request model for generating reports."""
    search_id: str
    formats: List[ReportFormat] = Field(
        default_factory=lambda: [ReportFormat.JSON],
        description="Report formats to generate"
    )
    include_raw: bool = Field(
        False,
        description="Include raw data in the report"
    )
    include_suppressed: bool = Field(
        False,
        description="Include suppressed/private accounts in the report"
    )

class ReportResponse(BaseModel):
    """Response model for report generation."""
    report_id: str
    search_id: str
    formats: Dict[ReportFormat, str] = Field(
        ...,
        description="Map of format to download URL or file path"
    )
    generated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the report was generated"
    )