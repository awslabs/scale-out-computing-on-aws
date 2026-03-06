# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0  

from pydantic import BaseModel

class SocaDCVInstance(BaseModel):
    private_dns: str
    alb_rule: str
    instance_id: str
