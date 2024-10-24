# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import redis
from utils.aws.secrets_manager import SocaSecret
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse
from typing import Optional
import os
from cachetools import TTLCache, cached

logger = logging.getLogger("soca_logger")


class SocaCacheClient:
    def __init__(
        self,
        cache_key_prefix: Optional[
            str
        ] = f"/soca/{os.environ.get('SOCA_CONFIGURATION')}/",
        is_admin: Optional[bool] = False,
    ):
        self.cache_key_prefix = cache_key_prefix
        self.cache_config = get_cache_config(is_admin=is_admin)
        logger.debug(f"Building CacheClient for: {self.cache_config}")
        self.cache_client = self.cache_config.get("cache_client")
        self.cache_info = self.cache_config.get("cache_info")
        self.redis = True if self.cache_info.get("engine") in {"valkey", "redis"} else False
        self.ttl_long = self.cache_info.get("ttl/long")
        self.ttl_short = self.cache_info.get("ttl/short")

    def key_fqdn(self, key):
        if isinstance(key, bytes):
            _key = key.decode("utf-8")
        else:
            _key = key

        if _key.startswith(self.cache_key_prefix):
            _sanitized_key = _key
        else:
            _sanitized_key = (
                f"{self.cache_key_prefix}{_key[1:] if _key.startswith('/') else _key}"
            )

        return _sanitized_key

    def is_enabled(self):
        logger.debug("Checking if cache is enabled")
        if self.cache_info.get("enabled"):
            return SocaResponse(success=True, message="Cache is enabled")
        else:
            return SocaResponse(
                success=False, message="Cache is not enabled on this environment"
            )

    def exists(self, key):
        try:
            logger.debug(f"Checking if {key} exist on the cache")
            if self.redis:
                _q = self.cache_client.exists(self.key_fqdn(key))
                if _q == 1:
                    return SocaResponse(success=True, message=f"{key} exists in cache")
                else:
                    return SocaResponse(
                        success=False, message=f"{key} does not exist in cache"
                    )
        except Exception as err:
            return SocaError.CACHE_ERROR(
                helper=f"Unable to check if {key} exist due to {err}"
            )

    def scan(self, match_pattern: str = "*"):
        try:
            cursor = "0"
            keys = []
            while cursor != 0:
                cursor, batch = self.cache_client.scan(
                    cursor=cursor, match=match_pattern
                )
                keys.extend(batch)

            return SocaResponse(
                success=True, message=[key.decode("utf-8") for key in keys]
            )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to scan cache due to {err}")

    def set(self, key, value, ex=None):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache Set {key=} -> {value=}")
        try:
            if self.redis:
                if not ex:
                    ex = self.ttl_long

                _q = self.cache_client.set(f"{self.key_fqdn(key)}", value, ex=ex)
                if _q:
                    return SocaResponse(
                        success=True, message=f"Key {key} cached successfully"
                    )
                else:
                    return SocaResponse(
                        success=False,
                        message=f"Unable to cache {key}. Redis Response: {_q}",
                    )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to cache {key} due to {err}")

    def delete(self, key):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache Delete {key=}")
        try:
            if self.redis:
                if self.exists(self.key_fqdn(key)).success:
                    _q = self.cache_client.delete(f"{self.key_fqdn(key)}")
                    if _q == 1:
                        return SocaResponse(
                            success=True, message=f"Key {key} deleted successfully"
                        )
                    else:
                        return SocaResponse(
                            success=False,
                            message=f"Unable to delete {key}. Redis Response: {_q}",
                        )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to delete {key} due to {err}")

    def get(self, key):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache Get {key=}")

        try:
            if self.redis:
                if self.exists(self.key_fqdn(key)).success:
                    return SocaResponse(
                        success=True, message=self.cache_client.get(self.key_fqdn(key))
                    )
                else:
                    logger.info(f"Key {key} does not exist in cache")
                    return SocaResponse(success=False, message="CACHE_MISS")
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to get {key} due to {err}")

    def lrange(self, key, start, end):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache lrange {key=}:  {start}-{end}")
        try:
            _output = []
            if self.redis:
                _range = self.cache_client.lrange(
                    self.key_fqdn(key), start=start, end=end
                )
                if _range:
                    for _item in _range:
                        _output.append(_item.decode("utf-8"))
                return SocaResponse(success=True, message=_output)
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to lrange {key} due to {err}")

    def lpush(self, key, *element):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache lpush {key=}")
        try:
            if self.redis:
                return SocaResponse(
                    success=True,
                    message=self.cache_client.lpush(self.key_fqdn(key), *element),
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to lpush {key} due to {err}")

    def rpush(self, key, *element):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache rpush {key=}")
        try:
            if self.redis:
                return SocaResponse(
                    success=True,
                    message=self.cache_client.rpush(self.key_fqdn(key), *element),
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to rpush {key} due to {err}")

    def ttl(self, key):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache TTL {key=}")
        try:
            if self.redis:
                return SocaResponse(
                    success=True, message=self.cache_client.ttl(self.key_fqdn(key))
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to ttl {key} due to {err}")

    def expire(self, key, ttl=0):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Cache expire {key=} {ttl=}")
        try:
            if self.redis:
                return SocaResponse(
                    success=True,
                    message=self.cache_client.expire(self.key_fqdn(key), ttl),
                )
        except Exception as err:
            return SocaError.CACHE_ERROR(helper=f"Unable to expire {key} due to {err}")


@cached(TTLCache(maxsize=30, ttl=86400))
def get_cache_config(is_admin: bool = False) -> dict:
    logger.debug(f"Building a cache_client)")
    _cache_info: dict = {}
    _ssm_client = utils_boto3.get_boto(service_name="ssm").message
    _ssm_key_path = f"/soca/{os.environ.get('SOCA_CONFIGURATION')}/configuration/Cache/"

    _ssm_paginator = _ssm_client.get_paginator("get_parameters_by_path")
    _ssm_iterator = _ssm_paginator.paginate(Path=_ssm_key_path, Recursive=True)

    for _page in _ssm_iterator:
        for _p in _page.get("Parameters", []):
            _cache_info[_p.get("Name").replace(_ssm_key_path, "")] = _p.get("Value")

    if _cache_info.get("enabled"):
        _get_credentials = (
            SocaSecret(secret_id="CacheAdminUser" if is_admin else "CacheReadOnlyUser")
            .get_secret()
            .get("message")
        )
        if _cache_info.get("engine") in {"valkey", "redis"}:
            _cache_client = redis.Redis(
                host=_cache_info.get("endpoint"),
                port=_cache_info.get("port"),
                protocol=3,
                ssl=True,
                ssl_cert_reqs=None,
                decode_responses=False,
                username=_get_credentials.get("username"),
                password=_get_credentials.get("password"),
            )
            logger.debug("Cache client built successfully")
        else:
            _cache_client = None
    else:
        logger.info("Cache not enabled, client is None")
        _cache_client = None

    return {"cache_client": _cache_client, "cache_info": _cache_info}
