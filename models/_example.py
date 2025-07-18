"""
Example usage of Maigret models with async/await patterns.

This module demonstrates how to use Maigret's models in an asynchronous context,
including database operations and API interactions.
"""
import asyncio
import aiohttp
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any

from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from aiohttp import ClientSession
from ._requets import SearchRequest, SearchScope
from ._response import AccountInfo, CheckStatus, SearchResult, BatchSearchResult
from ._error import ValidationError

# --- Example Pydantic Models ---

class SearchConfig(BaseModel):
    """Configuration for a search operation."""
    search_id: str
    request: SearchRequest
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = "pending"
    progress: float = 0.0
    
    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat(),
            HttpUrl: str
        }

# --- Example Database Models ---

class DatabaseManager:
    """Async database manager for search operations."""
    
    def __init__(self, db_url: str):
        self.engine = create_async_engine(db_url)
        self.async_session = sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )
    
    async def save_search_result(self, result: SearchResult) -> None:
        """Save search result to database asynchronously."""
        async with self.async_session() as session:
            # Example: Convert SearchResult to database model and save
            # db_result = SearchResultModel.from_pydantic(result)
            # session.add(db_result)
            await session.commit()
            return None
    
    async def get_search_history(
        self, 
        user_id: str, 
        days: int = 30
    ) -> List[Dict]:
        """Retrieve search history for a user."""
        # Example query implementation
        # async with self.async_session() as session:
        #     result = await session.execute(
        #         select(SearchResultModel)
        #         .where(SearchResultModel.user_id == user_id)
        #         .where(SearchResultModel.created_at >= datetime.utcnow() - timedelta(days=days))
        #     )
        #     return [r.to_dict() for r in result.scalars()]
        return []  # pragma: no cover

# --- Example API Client ---

class MaigretClient:
    """Async client for Maigret API operations."""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers={"Authorization": f"Bearer {self.api_key}"})
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def search_username(
        self, 
        username: str, 
        tags: Optional[List[str]] = None,
        timeout: int = 30
    ) -> SearchResult:
        """Search for a username across multiple sites asynchronously."""
        url = f"{self.base_url}/search"
        params = {"username": username, "timeout": timeout}
        if tags:
            params["tags"] = ",".join(tags)
        
        async with self.session.get(url, params=params) as response:
            if response.status != 200:
                error = await response.json()
                raise ValidationError(
                    error=error.get("error", "Search failed"),
                    code=response.status,
                    details=error
                )
            return SearchResult(**await response.json())
    
    async def batch_search(
        self,
        usernames: List[str],
        tags: Optional[List[str]] = None,
        max_concurrent: int = 5
    ) -> BatchSearchResult:
        """Perform batch username searches with concurrency control."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def limited_search(username: str) -> tuple[str, Optional[SearchResult]]:
            async with semaphore:
                try:
                    result = await self.search_username(username, tags)
                    return username, result
                except Exception:  # noqa: BLE001
                    return username, None  # type: ignore
        
        tasks = [limited_search(username) for username in usernames]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return BatchSearchResult(
            results=dict(r for r in results if r[1] is not None),
            errors={user: str(err) for user, err in results if isinstance(err, Exception)}
        )

# --- Example Usage ---

async def example_usage():
    """Demonstrate async usage of Maigret models and clients."""
    # Initialize database and client
    db = DatabaseManager("sqlite+aiosqlite:///maigret.db")
    
    # Example search request with validation
    _ = SearchRequest(
        usernames=["johndoe", "janedoe"],
        scope=SearchScope.TOP,
        max_sites=50,
        timeout=10,
        tags=["social", "programming"]
    )
    
    # Example account info (demonstrates model usage)
    _ = AccountInfo(
            username="johndoe",
        url=HttpUrl("https://github.com/johndoe"),
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
    
    # Example API client usage
    async with MaigretClient("https://api.maigret.example.com", "your-api-key") as client:
        try:
            # Single search
            result = await client.search_username("johndoe", tags=["social"])
            print(f"Found {len(result.accounts)} accounts for johndoe")
            
            # Batch search
            batch_result = await client.batch_search(
                ["johndoe", "janedoe", "nonexistent"],
                max_concurrent=3
            )
            print(f"Batch search completed with {len(batch_result.results)} results")
            
            # Save results to database
            for username, search_result in batch_result.results.items():
                await db.save_search_result(search_result)
                
        except ValidationError as e:
            print(f"Validation error: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

# Run the example
if __name__ == "__main__":
    asyncio.run(example_usage())