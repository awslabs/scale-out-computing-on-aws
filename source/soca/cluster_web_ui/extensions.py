######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import logging
import redis

logger = logging.getLogger("application")


def get_cache_config(provider: str = 'redis', **kwargs) -> dict:

    logger.debug(f"get_cache_config() - Looking for a cache provider ({provider}) ({kwargs})")
    _cache_config: dict = {}

    if provider == 'redis':
        _cache_config = _get_redis_config(**kwargs)
    else:
        logger.error(f"get_cache_config() - Unable to find a cache provider ({provider}) ({kwargs})")

    # TODO sanity check the cache provider return
    return _cache_config


def _get_redis_config(return_client: bool = True) -> dict:
    # todo: move this to param store
    logger.debug(f"_get_redis_config() - Building a redis cache_client (return_client={return_client})")
    _cache_client: dict = {}

    _redis_auth_username = open("/root/RedisAdminUsername.txt", "r").read().rstrip().lstrip()
    _redis_auth_password = open("/root/RedisAdminPassword.txt", "r").read().rstrip().lstrip()
    _redis_host = "localhost"
    _redis_port = 6379

    if return_client:
        _redis_client = redis.Redis(
            host=_redis_host,
            port=_redis_port,
            protocol=3,
            decode_responses=True,
            username=_redis_auth_username,
            password=_redis_auth_password
        )
    else:
        _redis_client = None

    _cache_client = {
        "cache_auth_username": _redis_auth_username,
        "cache_auth_password": _redis_auth_password,
        "cache_client": _redis_client
    }
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"_get_redis_config() - Returning cache_client {_cache_client.get('cache_client', 'unknown')}")

    return _cache_client
