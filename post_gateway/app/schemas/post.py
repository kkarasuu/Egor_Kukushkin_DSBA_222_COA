from pydantic import BaseModel
from typing import List, Optional

class PostCreate(BaseModel):
    title: str
    description: str
    is_private: bool = False
    tags: List[str] = []

class PostUpdate(BaseModel):
    title: Optional[str]
    description: Optional[str]
    is_private: Optional[bool]
    tags: Optional[List[str]]

class PostResponse(BaseModel):
    id: int
    title: str
    description: str
    creator_id: int
    created_at: str
    updated_at: str
    is_private: bool
    tags: List[str]
