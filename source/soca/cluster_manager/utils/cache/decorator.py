# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from utils.response import SocaResponse
from utils.cache.client import SocaCacheClient
import hashlib
import functools
import inspect
import pickle

logger = logging.getLogger("soca_logger")


def _check_response_filter(data, path, expected_value=None):
    """
    Helper to check if a nested path exists in data and optionally matches a value.
    Supports multiple levels of nesting using dot notation and array indexing.

    Args:
        data: The data structure to check (dict, list, SocaResponse, etc.)
        path: Dot-separated path string. Numeric keys are treated as array indices. Examples:
            - "state" (single level)
            - "message.state" (two levels)
            - "message.RootDeviceInfo.State" (three levels)
            - "Images.0.State" (array indexing - first element)
            - "data.attributes.metadata.status" (four levels)
        expected_value: Optional value to match. If None, just checks existence.

    Returns:
        True if path exists (and matches value if provided), False otherwise

    Examples:
        # Dict access
        data = {"message": {"RootDeviceInfo": {"State": "available"}}}
        _check_response_filter(data, "message.RootDeviceInfo.State", "available")  # True
        _check_response_filter(data, "message.RootDeviceInfo.State")  # True (exists)
        _check_response_filter(data, "message.RootDeviceInfo.Missing")  # False

        # Array access
        data = {"Images": [{"State": "available", "ImageId": "ami-123"}]}
        _check_response_filter(data, "Images.0.State", "available")  # True
        _check_response_filter(data, "Images.0.ImageId")  # True (exists)
        _check_response_filter(data, "Images.1.State")  # False (index out of range)
    """
    try:
        current = data
        keys = path.split(".")

        for key in keys:
            # Handle SocaResponse - unwrap to message
            if isinstance(current, SocaResponse):
                current = current.get("message", {})
                # After unwrapping, skip to next key if this was "message"
                if key == "message":
                    continue

            # Try to parse key as integer for array access
            try:
                index = int(key)
                if isinstance(current, (list, tuple)):
                    if 0 <= index < len(current):
                        current = current[index]
                    else:
                        return False  # Index out of range
                else:
                    return False  # Not an array
            except ValueError:
                # Not a number, treat as dict key
                if isinstance(current, dict):
                    if key not in current:
                        return False
                    current = current[key]
                else:
                    return False

        # If we got here, path exists
        if expected_value is not None:
            return current == expected_value
        return True
    except Exception:
        return False


def soca_cache(
    prefix: str, ttl: int = None, is_admin: bool = True, cache_if: callable = None
):
    """
    Decorator to cache function results in SocaCacheClient using pickle.

    Args:
        prefix: namespace for cache keys
        ttl: override TTL (defaults to SocaCacheClient.ttl_long if not set)
        is_admin: whether to use admin credentials for cache client (change to False is not using the SocaController)
        cache_if: optional callable that receives the result and returns True if it should be cached

    /!\ Only cache/return successful SocaResponse /!\

    Examples:
        # Basic usage - cache all successful responses
        @soca_cache(prefix="users", ttl=300)
        def get_user(user_id):
            return SocaResponse(success=True, message={"id": user_id, "name": "John"})

        # Cache only if nested path has specific value
        @soca_cache(prefix="images", cache_if=lambda r: _check_response_filter(r, "message.State", "available"))
        def describe_image(image_id):
            return SocaResponse(success=True, message={"State": "available", "ImageId": image_id})

        # Cache only if array element has specific value (AWS describe_images response)
        @soca_cache(prefix="images", cache_if=lambda r: _check_response_filter(r, "message.Images.0.State", "available"))
        def describe_images(image_id):
            # Returns: SocaResponse with message={"Images": [{"State": "available", ...}]}
            return SocaResponse(success=True, message=ec2_response)

        # Cache only if path exists
        @soca_cache(prefix="nodes", cache_if=lambda r: _check_response_filter(r, "message.state"))
        def get_node_status(node_id):
            return SocaResponse(success=True, message={"state": "running"})

        # Custom condition
        @soca_cache(prefix="data", cache_if=lambda r: r.get("message", {}).get("count", 0) > 0)
        def get_items():
            return SocaResponse(success=True, message={"count": 5, "items": [...]})

        # Invalidate cache for specific arguments
        get_user.invalidate_cache(user_id="123")

        # Invalidate all cached entries for this prefix
        get_user.invalidate_all()
    """
    cache_client = SocaCacheClient(is_admin=is_admin)

    def decorator(func):
        sig = inspect.signature(func)

        def make_cache_key(*args, **kwargs):
            """Generate a unique key based on func name + args"""
            bound = sig.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            key_bytes = pickle.dumps(
                (func.__module__, func.__qualname__, bound.arguments)
            )
            key_hash = hashlib.sha256(key_bytes).hexdigest()
            return f"{prefix}:{key_hash}"

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> SocaResponse:
            cache_key = make_cache_key(*args, **kwargs)
            logger.info(f"Trying to fetch {cache_key}")
            _cache_enabled = cache_client.is_enabled().success
            if _cache_enabled:
                cached_resp = cache_client.get(cache_key)
                if (
                    cached_resp.get("success")
                    and cached_resp.get("message") != "CACHE_MISS"
                ):
                    logger.info(
                        f"{cache_key} found on Cache, trying to unpickle payload"
                    )
                    try:
                        payload = cached_resp.message
                        if isinstance(payload, (bytes, bytearray)):
                            data = pickle.loads(payload)
                        else:
                            data = payload
                        logger.debug(f"Cached value: {data}")
                        logger.info("Successfully retrieved data from cache")
                        return data  # return the entire SocaResponse
                    except Exception as err:
                        logger.warning(
                            f"Failed to deserialize cache for {cache_key}: {err}"
                        )

            logger.info("Key not available on cache, calling actual function")
            result = func(*args, **kwargs)

            # Only cache successful and trusted SocaResponse
            # note: pickle does not handle input serialization, so make sure to only cache data from trusted sources
            should_cache = (
                isinstance(result, SocaResponse) and result.get("success") is True
            )
            if _cache_enabled:
                # Apply additional cache_if condition if provided
                if should_cache and cache_if is not None:
                    try:
                        should_cache = cache_if(result)
                        if not should_cache:
                            logger.warning(
                                f"cache_if condition not met for {cache_key}"
                            )
                    except Exception as err:
                        logger.warning(f"cache_if check failed for {cache_key}: {err}")
                        should_cache = False

                if should_cache:
                    try:
                        logger.debug(f"Caching {cache_key}")
                        _ttl = ttl or cache_client.ttl_long
                        cache_client.set(
                            key=cache_key,
                            value=pickle.dumps(result),
                            ex=_ttl,
                        )
                        logger.info(f"Successfully cached {cache_key}")
                    except Exception as err:
                        logger.warning(f"Failed to cache {cache_key}: {err}")
                else:
                    logger.warning(
                        "Result is not a successful SocaResponse or cache conditions not met, result wont be cached"
                    )

            return result

        def invalidate_cache(*args, **kwargs):
            cache_key = make_cache_key(*args, **kwargs)
            logger.info(f"Invalidating cache key {cache_key}")
            return cache_client.delete(cache_key)

        def invalidate_all():
            logger.info(f"Invalidating ALL cache keys for prefix {prefix}")
            # Scan matching keys and delete them
            scan_resp = cache_client.scan(match_pattern=f"{prefix}:*")
            if scan_resp.success:
                deleted = 0
                for k in scan_resp.message:
                    cache_client.delete(k)
                    deleted += 1
                return SocaResponse(success=True, message=f"Deleted {deleted} keys")
            else:
                return SocaResponse(success=False, message="Failed to scan keys")

        wrapper.build_cache_key = make_cache_key
        wrapper.invalidate_cache = invalidate_cache
        wrapper.invalidate_all = invalidate_all

        return wrapper

    return decorator
