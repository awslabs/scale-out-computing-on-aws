# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from typing import Optional


def get_boto_session_credentials():
    try:
        return boto3.Session().get_credentials()
    except Exception as err:
        raise f"Unable to get boto3 credentials because of {err}"


def get_boto_session_region():
    try:
        return boto3.Session().region_name
    except Exception as err:
        raise f"Unable to get boto3 region because of {err}"


def get_boto(
    service_name: str,
    region_name: Optional[str] = None,
    profile_name: Optional[str] = None,
    resource: Optional[bool] = False,
    endpoint_url: Optional[str] = None,
) -> boto3.session:

    if not region_name:
        region_name = get_boto_session_region()

    _boto3_params = {
        "service_name": service_name,
        "region_name": region_name,
        "endpoint_url": endpoint_url,
    }
    if profile_name is None:
        _session = boto3.Session()
    else:
        _session = boto3.Session(profile_name=profile_name)
    try:
        if not resource:
            return _session.client(**_boto3_params)
        else:
            return _session.resource(**_boto3_params)
    except Exception as err:
        raise f"Unable to create boto3 {'resource' if resource else 'client'} for {service_name} because of {err}"