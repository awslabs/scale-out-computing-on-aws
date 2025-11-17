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


def soca_cache(prefix: str, ttl: int = None, is_admin: bool = True):
    """
    Decorator to cache function results in SocaCacheClient using pickle.
    - prefix: namespace for cache keys
    - ttl: override TTL (defaults to SocaCacheClient.ttl_long if not set)
    - is_admin: whether to use admin credentials for cache client (change to False is not using the SocaController)

    /!\ Only cache/return successful SocaResponse /!\ 
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
            logger.debug(f"Trying to fetch {cache_key}")

            if cache_client.is_enabled().success:
                cached_resp = cache_client.get(cache_key)
                if (
                    cached_resp.get("success")
                    and cached_resp.get("message") != "CACHE_MISS"
                ):
                    logger.debug(
                        f"{cache_key} found on Cache, trying to unpickle payload"
                    )
                    try:
                        payload = cached_resp.message
                        if isinstance(payload, (bytes, bytearray)):
                            data = pickle.loads(payload)
                        else:
                            data = payload
                        logger.debug(f"Cached value: {data}")
                        return data  # return the entire SocaResponse
                    except Exception as err:
                        logger.warning(
                            f"Failed to deserialize cache for {cache_key}: {err}"
                        )

            logger.debug("Key not available on cache, calling actual function")
            result = func(*args, **kwargs)

            # Only cache successful and trusted SocaResponse
            # note: pickle does not handle input serialization, so make sure to only cache data from trusted sources
            if isinstance(result, SocaResponse) and result.get("success") is True:
                try:
                    logger.debug(f"Caching {cache_key}")
                    _ttl = ttl or cache_client.ttl_long
                    cache_client.set(
                        key=cache_key,
                        value=pickle.dumps(result),
                        ex=_ttl,
                    )
                    logger.debug(f"Successfully cached {cache_key}")
                except Exception as err:
                    logger.warning(f"Failed to cache {cache_key}: {err}")
            else:
                logger.warning(
                    "Result is not a successful SocaResponse, result wont be cached"
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
