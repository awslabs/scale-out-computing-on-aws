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

from __future__ import division
import ast
import base64
import datetime
import json
from typing import Any
import os
import re
import sys
from utils.aws.ssm_parameter_store import SocaConfig
from utils.analytics_client import SocaAnalyticsClient
from utils.logger import SocaLogger
from utils.error import SocaError
from utils.aws.boto3_wrapper import get_boto
from utils.cast import SocaCastEngine

# Update EBS rate for your region
# EBS Formulas: https://aws.amazon.com/ebs/pricing/
# Estimated cost provided by SOCA are estimates only. Refer to Cost Explorer for exact data

EBS_GP3_STORAGE_COST = 0.08  # $ per gb per month
EBS_GP2_STORAGE_COST = 0.125  # $ per gb per month
EBS_IO2_STORAGE_COST = 0.125  # $ per gb per month
EBS_PROVISIONED_IO_COST = 0.065  # IOPS per month
FSX_LUSTRE_COST = 0.000194  # GB per hour


def cast_wrapper(data: Any, cast_as: [str, list, float, int, dict]):
    _cast_attempt = SocaCastEngine(data=data).cast_as(cast_as)
    if _cast_attempt.success:
        return _cast_attempt.message
    else:
        SocaError.GENERIC_ERROR(
            helper=f"Unable to cast {data} as {cast_as}. {_cast_attempt}"
        )
        sys.exit(1)


def get_aws_pricing(ec2_instance_type):
    pricing = {}
    response = pricing_client.get_products(
        ServiceCode="AmazonEC2",
        Filters=[
            {
                "Type": "TERM_MATCH",
                "Field": "usageType",
                "Value": f"BoxUsage:{ec2_instance_type}",
            },
        ],
    )
    for data in response["PriceList"]:
        data = ast.literal_eval(data)
        for k, v in data["terms"].items():
            if k == "OnDemand":
                for skus in v.keys():
                    for ratecode in v[skus]["priceDimensions"].keys():
                        instance_data = v[skus]["priceDimensions"][ratecode]
                        if (
                            f"on demand linux {ec2_instance_type} instance hour"
                            in instance_data["description"].lower()
                        ):
                            pricing["ondemand"] = float(
                                instance_data["pricePerUnit"]["USD"]
                            )
            else:
                for skus in v.keys():
                    if (
                        v[skus]["termAttributes"]["OfferingClass"] == "standard"
                        and v[skus]["termAttributes"]["LeaseContractLength"] == "1yr"
                        and v[skus]["termAttributes"]["PurchaseOption"] == "No Upfront"
                    ):
                        for ratecode in v[skus]["priceDimensions"].keys():
                            instance_data = v[skus]["priceDimensions"][ratecode]
                            if (
                                "Linux/UNIX (Amazon VPC)"
                                in instance_data["description"]
                            ):
                                pricing["reserved"] = float(
                                    instance_data["pricePerUnit"]["USD"]
                                )

    return pricing


def job_already_indexed(job_uuid: str) -> bool:
    # Make sure the entry has not already been ingested on the OpenSearch cluster.
    # Job UUID is base64 encoded: <job_id>_<cluster_id>_<timestamp_when_job_completed>
    # We check if the job_uuid is found in the timedelta specified (default 60 days)
    _days_to_check = 60
    json_to_push = {
        "query": {
            "bool": {
                "must": [{"match": {"job_uuid": job_uuid}}],
                "filter": [
                    {
                        "range": {
                            "start_iso": {
                                "gte": (
                                    datetime.datetime.now()
                                    - datetime.timedelta(days=_days_to_check)
                                ).isoformat()
                                + "Z",
                                "lt": "now",
                            }
                        }
                    }
                ],
            },
        },
    }

    _search_result = _analytics_client.search(index=_index_name, body=json_to_push)
    if _search_result.success is True:
        if any(d.get("job_uuid") == job_uuid for d in _search_result.message) is True:
            logger.debug(f"Job {job_uuid} already indexed")
            return True
        else:
            logger.info(f"Job {job_uuid} not present in index, data can be indexed")
            return False
    return False


def read_file(filename: str) -> str:
    logger.info(f"Opening {filename}")
    try:
        log_file = open(filename, "r")
        content = log_file.read()
        log_file.close()
    except FileNotFoundError:
        # handle case where file does not exist
        logger.warning(f"{filename} does not exist, ignoring ...")
        content = ""
    except Exception as err:
        SocaError.ANALYTICS_ERROR(helper=f"Unable to read {filename} due to {err}")
        sys.exit(1)

    return content


if __name__ == "__main__":
    _index_name = "soca_jobs"
    _accounting_log_path = "/var/spool/pbs/server_priv/accounting/"

    # Choose the number of days you want to ingest, default to 3
    days_to_ingest = 3
    last_day_to_ingest = datetime.datetime.now()
    date_to_check = [
        last_day_to_ingest - datetime.timedelta(days=x) for x in range(days_to_ingest)
    ]

    ec2_client = get_boto(service_name="ec2").message
    pricing_client = get_boto(service_name="pricing", region_name="us-east-1").message

    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().message
    _log_file_location = (
        f"/opt/soca/{_cluster_id}/cluster_manager/analytics/logs/job_tracking.log"
    )
    logger = SocaLogger(name="analytics_job_tracking").rotating_file_handler(
        file_path=_log_file_location
    )

    logger.info(f"Tracking active HPC jobs . Log: {_log_file_location}")

    _analytics_client = SocaAnalyticsClient(
        endpoint=SocaConfig(key="/configuration/Analytics/endpoint")
        .get_value()
        .get("message"),
        engine=SocaConfig(key="/configuration/Analytics/engine")
        .get_value()
        .get("message"),
    )

    if _analytics_client.is_enabled().success is False:
        logger.info("Analytics is not enabled, exiting")
        sys.exit(1)
    else:
        _analytics_client.initialize()
        logger.info("Analytics client initialized")

    pricing_table = {}
    management_chain_per_user = {}
    json_output = []
    output = {}

    for day in date_to_check:
        scheduler_log_format = day.strftime("%Y%m%d")
        response = read_file(f"{_accounting_log_path}{scheduler_log_format}")
        try:
            for line in response.splitlines():
                logger.debug(f"Processing {line}")
                try:
                    data = (line.rstrip()).split(";")
                    if data.__len__() != 4:
                        logger.debug("Line length is not 4, ignoring")
                    else:
                        timestamp = data[0]
                        job_state = data[1]
                        job_id = data[2].split(".")[0]
                        job_data = data[3]
                        logger.debug(
                            f"Valid line detected, timestamp {timestamp}, job_state {job_state}, job_id {job_id}, job_data {job_data}"
                        )

                        if job_id in output.keys():
                            output[job_id].append(
                                {
                                    "utc_date": timestamp,
                                    "job_state": job_state,
                                    "job_id": job_id,
                                    "job_data": job_data,
                                }
                            )
                        else:
                            output[job_id] = [
                                {
                                    "utc_date": timestamp,
                                    "job_state": job_state,
                                    "job_id": job_id,
                                    "job_data": job_data,
                                }
                            ]
                except Exception as err:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    SocaError.GENERIC_ERROR(
                        helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
                    )
                    sys.exit(1)

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )
            sys.exit(1)

    for job_id, values in output.items():
        logger.debug(
            f"Checking if {job_id} can be index, ignoring all lines where job_state is not 'e'"
        )
        try:
            for data in values:
                try:
                    if data["job_state"].lower() == "e":
                        logger.debug(f"Valid job state, processing  {data}")
                        ignore = False
                        if "Resource_List.instance_type" not in data["job_data"]:
                            logger.info(
                                f"No instance type found for {job_id}, ignoring ... "
                            )
                            ignore = True
                        else:
                            queue = re.search(r"queue=(\w+)", data["job_data"]).group(1)

                        if ignore is False:
                            used_resources = re.findall(
                                r"(\w+)=([^\s]+)", data["job_data"]
                            )
                            logger.debug(f"Checking used resources: {used_resources}")
                            if used_resources:
                                job_info = {"job_id": job_id}
                                for res in used_resources:
                                    resource_name = res[0]
                                    resource_value = res[1]

                                    if resource_name == "select":
                                        # Extract meaningful info in select
                                        job_info["nodect"] = cast_wrapper(
                                            data=resource_value.split(":")[0],
                                            cast_as=int,
                                        )

                                        _options = {
                                            "mpiprocs": {
                                                "regex": "mpiprocs=(\d+)",
                                                "type": int,
                                            },
                                            "ppn": {"regex": "ppn=(\d+)", "type": int},
                                            "ncpus": {
                                                "regex": "ncpus=(\d+)",
                                                "type": int,
                                            },
                                        }

                                        for attr_name, attr_info in _options.items():
                                            _attr_exist = re.search(
                                                attr_info.get("regex"), resource_value
                                            )
                                            if _attr_exist:
                                                job_info[attr_name] = cast_wrapper(
                                                    data=_attr_exist.group(1),
                                                    cast_as=attr_info.get("type"),
                                                )

                                        # Finally add the entire select as str
                                        job_info["select"] = str(resource_value)

                                    elif resource_name in [
                                        "start",
                                        "end",
                                        "qtime",
                                        "ctime",
                                        "etime",
                                        "Exit_status",
                                        "root_size",
                                        "scratch_size",
                                    ]:
                                        # Cast safe value to int
                                        job_info[resource_name] = cast_wrapper(
                                            data=resource_value, cast_as=int
                                        )

                                    else:
                                        # Force cast everything else as string to avoid case where you start indexing as long/integer (eg: -l select=3)
                                        # and then you include some string value (eg: -l select=3:ppn=12)
                                        job_info[resource_name] = str(resource_value)

                                # Adding custom field to index
                                job_info["soca_cluster_id"] = _cluster_id
                                job_info["simulation_time_seconds"] = (
                                    job_info["end"] - job_info["start"]
                                )
                                job_info["simulation_time_minutes"] = cast_wrapper(
                                    data=job_info["simulation_time_seconds"] / 60,
                                    cast_as=float,
                                )

                                job_info["simulation_time_hours"] = cast_wrapper(
                                    data=job_info["simulation_time_minutes"] / 60,
                                    cast_as=float,
                                )

                                job_info["simulation_time_days"] = cast_wrapper(
                                    data=job_info["simulation_time_hours"] / 24,
                                    cast_as=float,
                                )

                                job_info["mem_kb"] = int(
                                    job_info["mem"].replace("kb", "")
                                )
                                job_info["vmem_kb"] = int(
                                    job_info["vmem"].replace("kb", "")
                                )
                                job_info["qtime_iso"] = datetime.datetime.fromtimestamp(
                                    job_info["qtime"]
                                ).isoformat()
                                job_info["etime_iso"] = datetime.datetime.fromtimestamp(
                                    job_info["etime"]
                                ).isoformat()
                                job_info["ctime_iso"] = datetime.datetime.fromtimestamp(
                                    job_info["ctime"]
                                ).isoformat()
                                job_info["start_iso"] = datetime.datetime.fromtimestamp(
                                    job_info["start"]
                                ).isoformat()
                                job_info["end_iso"] = datetime.datetime.fromtimestamp(
                                    job_info["end"]
                                ).isoformat()

                                # Note: create a Job UUID, we will use it to ensure we don't index the same job twice
                                job_info["job_uuid"] = base64.b64encode(
                                    f"{job_id}_{_cluster_id}_{job_info['end_iso']}".encode(
                                        "utf-8"
                                    )
                                ).decode("utf-8")

                                # Calculate price of the simulation
                                # ESTIMATE ONLY. Refer to AWS Cost Explorer for exact data

                                # Note 1: This calculates the price of the simulation based on run time only.
                                # It does not include the time for EC2 to be launched and configured, so I artificially added a 5 minutes penalty (average time for an EC2 instance to be provisioned)

                                EC2_BOOT_DELAY = 300

                                simulation_time_seconds_with_penalty = (
                                    job_info["simulation_time_seconds"] + EC2_BOOT_DELAY
                                )
                                job_info["estimated_price_storage_scratch_iops"] = 0
                                job_info["estimated_price_storage_root_size"] = (
                                    0  # alwayson
                                )
                                job_info["estimated_price_storage_scratch_size"] = 0
                                job_info["estimated_price_fsx_lustre"] = 0

                                if "root_size" in job_info.keys():
                                    job_info["estimated_price_storage_root_size"] = (
                                        (
                                            job_info["root_size"]
                                            * EBS_GP3_STORAGE_COST
                                            * simulation_time_seconds_with_penalty
                                        )
                                        / (86400 * 30)
                                    ) * job_info["nodect"]

                                if "scratch_size" in job_info.keys():
                                    if "scratch_iops" in job_info.keys():
                                        job_info[
                                            "estimated_price_storage_scratch_size"
                                        ] = (
                                            (
                                                int(job_info["scratch_size"])
                                                * EBS_IO2_STORAGE_COST
                                                * simulation_time_seconds_with_penalty
                                            )
                                            / (86400 * 30)
                                        ) * job_info[
                                            "nodect"
                                        ]
                                        job_info[
                                            "estimated_price_storage_scratch_iops"
                                        ] = (
                                            (
                                                int(job_info["scratch_iops"])
                                                * EBS_PROVISIONED_IO_COST
                                                * simulation_time_seconds_with_penalty
                                            )
                                            / (86400 * 30)
                                        ) * job_info[
                                            "nodect"
                                        ]
                                    else:
                                        job_info[
                                            "estimated_price_storage_scratch_size"
                                        ] = (
                                            (
                                                int(job_info["scratch_size"])
                                                * EBS_GP3_STORAGE_COST
                                                * simulation_time_seconds_with_penalty
                                            )
                                            / (86400 * 30)
                                        ) * job_info[
                                            "nodect"
                                        ]

                                if "fsx_lustre_bucket" in job_info.keys():
                                    if job_info["fsx_lustre_bucket"] != "false":
                                        if "fsx_lustre_size" in job_info.keys():
                                            job_info["estimated_price_fsx_lustre"] = (
                                                job_info["fsx_lustre_size"]
                                                * FSX_LUSTRE_COST
                                                * (
                                                    simulation_time_seconds_with_penalty
                                                    / 3600
                                                )
                                            )
                                        else:
                                            # default lustre size
                                            job_info["estimated_price_fsx_lustre"] = (
                                                1200
                                                * FSX_LUSTRE_COST
                                                * (
                                                    simulation_time_seconds_with_penalty
                                                    / 3600
                                                )
                                            )

                                if (
                                    job_info["instance_type"].split("+")[0]
                                    not in pricing_table.keys()
                                ):
                                    pricing_table[
                                        job_info["instance_type"].split("+")[0]
                                    ] = get_aws_pricing(
                                        job_info["instance_type"].split("+")[0]
                                    )

                                job_info["estimated_price_ec2_ondemand"] = (
                                    simulation_time_seconds_with_penalty
                                    * (
                                        pricing_table[
                                            job_info["instance_type"].split("+")[0]
                                        ]["ondemand"]
                                        / 3600
                                    )
                                    * job_info["nodect"]
                                )
                                reserved_hourly_rate = (
                                    pricing_table[
                                        job_info["instance_type"].split("+")[0]
                                    ]["reserved"]
                                    / 750
                                )
                                job_info["estimated_price_ec2_reserved"] = (
                                    simulation_time_seconds_with_penalty
                                    * (reserved_hourly_rate / 3600)
                                    * job_info["nodect"]
                                )

                                job_info["estimated_price_ondemand"] = (
                                    job_info["estimated_price_ec2_ondemand"]
                                    + job_info["estimated_price_storage_root_size"]
                                    + job_info["estimated_price_storage_scratch_size"]
                                    + job_info["estimated_price_storage_scratch_iops"]
                                    + job_info["estimated_price_fsx_lustre"]
                                )
                                job_info["estimated_price_reserved"] = (
                                    job_info["estimated_price_ec2_reserved"]
                                    + job_info["estimated_price_storage_root_size"]
                                    + job_info["estimated_price_storage_scratch_size"]
                                    + job_info["estimated_price_storage_scratch_iops"]
                                    + job_info["estimated_price_fsx_lustre"]
                                )

                                json_output.append(job_info)
                except Exception as err:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    SocaError.GENERIC_ERROR(
                        helper=f"Error with {data} for job id {job_id} - {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
                    )
                    sys.exit(1)

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )
            sys.exit(1)

    _index_exist = _analytics_client.index_exist(index=_index_name)
    for entry in json_output:
        if _index_exist.success is False:
            logger.info(
                f"Index {_index_name} does not exist, creating it automatically "
            )
            _analytics_client.index(index=_index_name, body=json.dumps(entry))
        else:
            logger.debug(
                f"Index {_index_name} already exist, checking if {entry['job_uuid']} is not already indexed"
            )
            if job_already_indexed(f"{entry['job_uuid']}") is False:
                _analytics_client.index(index=_index_name, body=json.dumps(entry))
                logger.info(f"{entry['job_uuid']} indexed successfully ")
            else:
                logger.debug(f"{entry['job_uuid']} already indexed")
