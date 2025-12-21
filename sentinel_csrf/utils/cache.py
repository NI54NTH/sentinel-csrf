"""
Input caching utilities for workflow optimization.

Provides local caching of request and cookie inputs for reuse.
Cache is stored in ~/.sentinel-csrf/cache/
"""

import os
from pathlib import Path
from typing import Optional, Tuple


# Cache directory location
CACHE_DIR = Path.home() / ".sentinel-csrf" / "cache"
LAST_REQUEST_FILE = "last-request.txt"
LAST_COOKIES_FILE = "last-cookies.txt"


def get_cache_dir() -> Path:
    """Get the cache directory, creating it if needed."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR


def cache_request(content: str) -> Path:
    """Cache a request to the local cache directory."""
    cache_dir = get_cache_dir()
    cache_path = cache_dir / LAST_REQUEST_FILE
    cache_path.write_text(content)
    return cache_path


def cache_cookies(content: str) -> Path:
    """Cache cookies to the local cache directory."""
    cache_dir = get_cache_dir()
    cache_path = cache_dir / LAST_COOKIES_FILE
    cache_path.write_text(content)
    return cache_path


def get_cached_request() -> Optional[str]:
    """Get the last cached request, if available."""
    cache_path = get_cache_dir() / LAST_REQUEST_FILE
    if cache_path.exists():
        return cache_path.read_text()
    return None


def get_cached_cookies() -> Optional[str]:
    """Get the last cached cookies, if available."""
    cache_path = get_cache_dir() / LAST_COOKIES_FILE
    if cache_path.exists():
        return cache_path.read_text()
    return None


def get_cached_request_path() -> Optional[Path]:
    """Get the path to the cached request file, if it exists."""
    cache_path = get_cache_dir() / LAST_REQUEST_FILE
    return cache_path if cache_path.exists() else None


def get_cached_cookies_path() -> Optional[Path]:
    """Get the path to the cached cookies file, if it exists."""
    cache_path = get_cache_dir() / LAST_COOKIES_FILE
    return cache_path if cache_path.exists() else None


def cache_both(request_content: str, cookies_content: str) -> Tuple[Path, Path]:
    """Cache both request and cookies."""
    return cache_request(request_content), cache_cookies(cookies_content)


def clear_cache() -> None:
    """Clear all cached inputs."""
    cache_dir = get_cache_dir()
    for file in [LAST_REQUEST_FILE, LAST_COOKIES_FILE]:
        cache_path = cache_dir / file
        if cache_path.exists():
            cache_path.unlink()
