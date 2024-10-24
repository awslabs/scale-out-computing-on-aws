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

import cfnresponse
import boto3
import logging
import json

"""
Populate AOSS Data Policy
"""
logging.getLogger().setLevel(logging.INFO)

iam_client = boto3.client("iam")
aoss_client = boto3.client("opensearchserverless")


def lambda_handler(event, context):

    logging.info(f"Event Details: {event}")
    _cluster_id: str = event.get("ResourceProperties", {}).get("ClusterId", "")

    try:

        _req_type: str = event.get("RequestType", "")
        if _req_type == "Delete":
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "")
            return

        # TODO - UPDATE  ? All other events to filter?

        if not _cluster_id:
            msg = f"ClusterId not found in Event: {event}"
            logging.error(msg)
            cfnresponse.send(event, context, cfnresponse.FAILED, {"error": msg}, msg)
            return

        logging.info(f"Creating Data Policy for ClusterId: {_cluster_id}")

        # Lookup the Principal IAM
        _principals: list = []
        _iam_page = iam_client.get_paginator("list_roles")
        _iam_iter = _iam_page.paginate()
        for _page in _iam_iter:
            for _role in _page.get("Roles", {}):
                _role_name = _role.get("RoleName", "")
                logging.info(f"Considering IAM Role: {_role_name}")
                if (
                    _role_name.startswith(f"soca-{_cluster_id}-ControllerRole") or
                    _role_name.startswith(f"soca-{_cluster_id}-ComputeNodeRole") or
                    _role_name.startswith(f"soca-{_cluster_id}-LoginNodeRole")
                ):
                    _role_arn = _role.get("Arn", "")
                    if _role_arn:
                        logging.info(f"Found cluster-related role: {_role_name}   (ARN: {_role_arn})")
                        _principals.append(_role_arn)

        # Who do we have?
        if _principals:
            logging.info(f"Found {len(_principals)} principals for cluster: {_principals}")

            # Validate the AOSS collection is ready
            # FIXME TODO - auto-retry?
            _collections = aoss_client.list_collections(
                collectionFilters=[
                    {"name": _cluster_id},
                    {"status": "ACTIVE"},
                ]
            )
            for _collection in _collections.get("collectionSummaries", []):
                _collection_arn: str = _collection.get("arn", "")
                logging.info(f"Potential AOSS collection for Cluster: {_collection} (ARN: {_collection_arn})")

                if _collection.get("name", "") == f"{_cluster_id}-analytics":
                    logging.info(f"Found AOSS collection: {_cluster_id}")

            # Create the data policy
            _policy_name: str = f"soca-{_cluster_id}-data-policy"
            _policy_doc: list = [
                {
                    "Description":  f"{_cluster_id} Data Policy",
                    "Rules": [
                        {
                            "ResourceType":  "collection",
                            "Resource": [
                                f"collection/{_cluster_id}-analytics",
                            ],
                            "Permission": [
                                "aoss:CreateCollectionItems",
                                "aoss:DeleteCollectionItems",
                                "aoss:DescribeCollectionItems",
                                "aoss:UpdateCollectionItems",
                            ],
                        },
                        {
                            "ResourceType": "index",
                            "Resource": [
                                f"index/{_cluster_id}-analytics/*",
                            ],
                            "Permission": [
                                "aoss:CreateIndex",
                                "aoss:DeleteIndex",
                                "aoss:DescribeIndex",
                                "aoss:UpdateIndex",
                                "aoss:ReadDocument",
                                "aoss:WriteDocument",
                            ],
                        }
                    ],
                    "Principal": _principals,
                }
            ]
            logging.info(f"Creating AOSS Data Policy: {_policy_name} with {_policy_doc}")
            _response = aoss_client.batch_create_data_policy(
                name=_policy_name,
                policy=json.dumps(_policy_doc),
                type="data",
            )
            logging.info(f"AOSS Data Policy creation response: {_response}")
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "")

    except:
        logging.exception("Caught exception")
        error_message = (
            f"Exception getting IAM information for cluster {_cluster_id}"
        )
        cfnresponse.send(
            event, context, cfnresponse.FAILED, {"error": error_message}, error_message
        )
