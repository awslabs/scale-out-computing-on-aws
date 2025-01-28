# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import json
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse
from typing import Optional

logger = logging.getLogger("soca_logger")


class SocaSecret:
    def __init__(
        self,
        secret_id: str,
        secret_id_prefix: Optional[
            str
        ] = f"/soca/{os.environ.get('SOCA_CLUSTER_ID')}/",
    ):
        self._secret_id = f"{secret_id_prefix}{secret_id}"

    def get_secret(self) -> SocaResponse:
        logger.debug(f"Retrieving secret {self._secret_id} from secretsmanager ")
        _sm_client = utils_boto3.get_boto(service_name="secretsmanager").message
        try:
            _fetch_secret = _sm_client.get_secret_value(SecretId=self._secret_id)
            logger.debug(f"Fetch Secret Response: {_fetch_secret}")
            if _fetch_secret.get("SecretString", None) is None:
                return SocaError.AWS_API_ERROR(
                    service_name="secretsmanager",
                    helper=f" SecretId {self._secret_id} exists but is empty",
                )
            else:
                try:
                    _secret_string = json.loads(_fetch_secret.get("SecretString"))
                    logger.debug(
                        f"SecretString for Secret {self._secret_id} retrieved successfully"
                    )
                    return SocaResponse(success=True, message=_secret_string)
                except Exception as e:
                    return SocaError.AWS_API_ERROR(
                        service_name="secretsmanager",
                        helper=f"SecretString returned but unable to load as json due to {e}",
                    )

        except _sm_client.exceptions.ResourceNotFoundException:
            return SocaError.AWS_API_ERROR(
                service_name="secretsmanager",
                helper=f"ResourceNotFoundException - SecretId {self._secret_id} does not exist",
            )

        except Exception as e:
            return SocaError.AWS_API_ERROR(
                service_name="secretsmanager",
                helper=f"Unknown error while trying to retrieve secret {self._secret_id}. Trace: {e}",
            )
           