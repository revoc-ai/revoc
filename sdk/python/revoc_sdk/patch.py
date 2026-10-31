"""revoc_sdk.patch — zero-code-change activation for existing OpenAI clients.

Calling :func:`patch` once at process startup monkey-patches
``openai.OpenAI.__init__`` and ``openai.AsyncOpenAI.__init__`` so that *any*
existing code that constructs an ``OpenAI()`` or ``AsyncOpenAI()`` client is
transparently routed through REVOC — provided the ``REVOC_BASE_URL``
environment variable is set. No source changes required (SPEC.md Section 2).

    export REVOC_BASE_URL=http://revoc:8080
"""

from __future__ import annotations

import os
from typing import Any

import openai

_PATCHED_ATTR = "_revoc_patched"
_ORIGINAL_SYNC_INIT_ATTR = "_revoc_original_sync_init"
_ORIGINAL_ASYNC_INIT_ATTR = "_revoc_original_async_init"


def patch() -> None:
    """Monkey-patch ``openai.OpenAI``/``openai.AsyncOpenAI`` to honor REVOC_BASE_URL.

    Idempotent — calling this more than once is a no-op after the first call.
    If ``REVOC_BASE_URL`` is not set at call time, this function does nothing
    (existing client construction behaves exactly as before).
    """
    revoc_url = os.environ.get("REVOC_BASE_URL")
    if not revoc_url:
        return

    if getattr(openai.OpenAI, _PATCHED_ATTR, False):
        return

    _original_sync_init = openai.OpenAI.__init__
    _original_async_init = openai.AsyncOpenAI.__init__

    def _patched_sync_init(self: openai.OpenAI, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("base_url", os.environ.get("REVOC_BASE_URL"))
        _original_sync_init(self, *args, **kwargs)

    def _patched_async_init(self: openai.AsyncOpenAI, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("base_url", os.environ.get("REVOC_BASE_URL"))
        _original_async_init(self, *args, **kwargs)

    setattr(openai.OpenAI, _ORIGINAL_SYNC_INIT_ATTR, _original_sync_init)
    setattr(openai.AsyncOpenAI, _ORIGINAL_ASYNC_INIT_ATTR, _original_async_init)
    openai.OpenAI.__init__ = _patched_sync_init  # type: ignore[method-assign]
    openai.AsyncOpenAI.__init__ = _patched_async_init  # type: ignore[method-assign]
    setattr(openai.OpenAI, _PATCHED_ATTR, True)
    setattr(openai.AsyncOpenAI, _PATCHED_ATTR, True)


def unpatch() -> None:
    """Reverse the effect of :func:`patch`.

    Restores ``openai.OpenAI.__init__`` and ``openai.AsyncOpenAI.__init__`` to
    their pre-patch implementations. Idempotent — calling this when no patch
    is active (or more than once) is a no-op.
    """
    if not getattr(openai.OpenAI, _PATCHED_ATTR, False):
        return

    original_sync_init = getattr(openai.OpenAI, _ORIGINAL_SYNC_INIT_ATTR)
    original_async_init = getattr(openai.AsyncOpenAI, _ORIGINAL_ASYNC_INIT_ATTR)

    openai.OpenAI.__init__ = original_sync_init  # type: ignore[method-assign]
    openai.AsyncOpenAI.__init__ = original_async_init  # type: ignore[method-assign]

    delattr(openai.OpenAI, _PATCHED_ATTR)
    delattr(openai.AsyncOpenAI, _PATCHED_ATTR)
    delattr(openai.OpenAI, _ORIGINAL_SYNC_INIT_ATTR)
    delattr(openai.AsyncOpenAI, _ORIGINAL_ASYNC_INIT_ATTR)
