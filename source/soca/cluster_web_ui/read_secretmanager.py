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

import json
import boto3
import os
import config
import time
import logging
import extensions

import redis

logger = logging.getLogger("application")


def get_soca_configuration():
    _start_time: int = time.perf_counter_ns()
    _return_result = None
    _configuration_secret_name: str = os.environ["SOCA_CONFIGURATION"]
    _cache_configuration_key: str = f"soca:{_configuration_secret_name}:cache:configuration"

    logger.debug(f"get_soca_configuration() - Retrieving configuration for cluster {_configuration_secret_name}")

    _cache_config = extensions.get_cache_config(
        provider='redis',
        return_client=True
    )

    _cache_client = _cache_config.get("cache_client", None)
    if not _cache_client:
        logger.error("Unable to retrieve cache_client from extensions.get_cache_config()")
        return None

    _conf_ttl: int = _cache_client.ttl(_cache_configuration_key)
    _config_check_ms: float = (time.perf_counter_ns() - _start_time) / 1_000_000

    logger.debug(f"Config TTL check completed in {_config_check_ms} ms")

    if _conf_ttl <= 0:
        _start_sm_time: int = time.perf_counter_ns()

        secretsmanager_client = boto3.client(
            "secretsmanager", config=config.boto_extra_config()
        )

        response = secretsmanager_client.get_secret_value(
            SecretId=_configuration_secret_name
        )
        _sm_duration_ms: float = (time.perf_counter_ns() - _start_sm_time) / 1_000_000
        logger.debug(f"get_soca_configuration() API from secretsmanager took {_sm_duration_ms} ms")

        if response.get("SecretString", None) is None:
            logger.error(f"Unable to retrieve configuration from secretsmanager")
            _return_result = None

        _start_cache_set = time.perf_counter_ns()
        # Since the configuration is not in redis, we get it from secretsmanager and store it in redis for a short time
        _return_result = response.get("SecretString")
        _cache_client.set(_cache_configuration_key, _return_result, ex=300)
        _cache_set_duration_ms: float = (time.perf_counter_ns() - _start_cache_set) / 1_000_000
        logger.debug(f"get_soca_configuration() - storing config into cache for 300 seconds (took {_cache_set_duration_ms} ms)")
    else:
        logger.debug(f"get_soca_configuration() - Valid Cache TTL for config cache - {_conf_ttl} seconds remaining")
        _return_result = _cache_client.get(_cache_configuration_key)

    _duration_ms: float = (time.perf_counter_ns() - _start_time) / 1_000_000
    logger.debug(f"get_soca_configuration() config took {_duration_ms} ms")
    return json.loads(_return_result, strict=False)

