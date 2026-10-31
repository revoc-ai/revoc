from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int = 1
    page_size: int = 50
    has_next: bool


class ErrorResponse(BaseModel):
    code: str
    message: str
    compilation_errors: list[str] | None = None


class MessageResponse(BaseModel):
    message: str
