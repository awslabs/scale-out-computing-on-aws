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

from flask_restful import Resource, reqparse
import logging
import ast
import re
import math
import utils.aws.boto3_wrapper as utils_boto3
from utils.response import SocaResponse
from utils.aws.ssm_parameter_store import SocaConfig

logger = logging.getLogger("soca_logger")


def get_compute_pricing(instance_type: str) -> dict:
    _pricing = {}
    client_pricing = utils_boto3.get_boto(
        service_name="pricing", region_name="us-east-1"
    ).message

    region = SocaConfig(key="/configuration/Region").get_value().message

    response = client_pricing.get_products(
        ServiceCode="AmazonEC2",
        Filters=[
            {
                "Type": "TERM_MATCH",
                "Field": "instanceType",
                "Value": instance_type,
            },
            {
                "Type": "TERM_MATCH",
                "Field": "regionCode",
                "Value": region,
            },
            {
                "Type": "TERM_MATCH",
                "Field": "operatingSystem",
                "Value": "Linux",
            },
            {
                "Type": "TERM_MATCH",
                "Field": "tenancy",
                "Value": "Shared",
            },
        ],
    )
    logger.debug(f"Retrieving pricing information for {instance_type}: {response}")
    for data in response["PriceList"]:
        _price_list = ast.literal_eval(data)
        for term_type, term_data in _price_list["terms"].items():
            for sku, sku_data in term_data.items():
                for rate_code, price_dimension in sku_data["priceDimensions"].items():
                    description = price_dimension["description"].lower()
                    price = float(price_dimension["pricePerUnit"]["USD"])

                    # On-Demand Pricing
                    if (
                        term_type == "OnDemand"
                        and f"on demand linux {instance_type} instance hour"
                        in description.lower()
                    ):
                        _pricing["ondemand"] = price

                    # Reserved Pricing (1 year, no upfront)
                    elif (
                        term_type != "OnDemand"
                        and sku_data["termAttributes"]["OfferingClass"] == "standard"
                        and sku_data["termAttributes"]["LeaseContractLength"] == "1yr"
                        and sku_data["termAttributes"]["PurchaseOption"] == "No Upfront"
                        and "linux/unix (amazon vpc)" in description.lower()
                    ):
                        _pricing["reserved"] = price
    return _pricing


class AwsPrice(Resource):
    def get(self):
        """
        Return RI/OD price based on compute/storage inputs
        ---
        tags:
          - AWS
        responses:
          200:
            description: The Pair of user/token is valid
          203:
            description: Invalid user/token pair
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("instance_type", type=str, location="args")
        parser.add_argument(
            "wall_time",
            type=str,
            location="args",
            help="Please specify wall_time using HH:MM:SS format",
            default="01:00:00",
        )
        parser.add_argument(
            "cpus",
            type=int,
            location="args",
            help="Please specify how many cpus you want to allocate",
        )
        parser.add_argument(
            "scratch_size",
            type=int,
            location="args",
            help="Please specify storage in GB to allocate to /scratch partition (Default 0)",
            default=0,
        )
        parser.add_argument(
            "root_size",
            type=int,
            location="args",
            help="Please specify your AMI root disk space (Default 10gb)",
            default=40,
        )
        parser.add_argument(
            "fsx_capacity",
            type=int,
            location="args",
            help="Please specify fsx_storage in GB",
            default=0,
        )
        parser.add_argument("fsx_type", type=str, location="args", default="SCRATCH_2")
        args = parser.parse_args()
        instance_type = args["instance_type"]
        scratch_size = args["scratch_size"]
        root_size = args["root_size"]
        fsx_storage = args["fsx_capacity"]
        fsx_type = args["fsx_type"]
        cpus = args["cpus"]
        sim_cost = {}

        # Change value below as needed if you use a different region
        EBS_GP3_STORAGE_BASELINE = 0.08  # us-east-1 0.08 cts per gb per month
        FSX_STORAGE_BASELINE = 0.13  # us-east-1 Persistent (50 MB/s/TiB baseline, up to 1.3 GB/s/TiB burst)  Scratch (200 MB/s/TiB baseline, up to 1.3 GB/s/TiB burst)

        try:
            sim_hours, sim_minutes, sim_seconds = map(
                float, args["wall_time"].split(":")
            )

        except ValueError:
            return SocaResponse(
                success=False,
                message="wall_time must use HH:MM:SS format and only use valid numbers",
            ).as_flask()

        walltime = sim_hours + (sim_minutes / 60) + (sim_seconds / 3600)

        # Calculate number of nodes required based on instance type and CPUs (not vCPUs) requested
        if cpus is None:
            nodect = 1
        else:
            cpus_count_pattern = re.search(r"[.](\d+)", instance_type)
            if cpus_count_pattern:
                cpu_per_system = int(cpus_count_pattern.group(1)) * 2
            else:
                if re.search(r"[.](xlarge)", instance_type):
                    cpu_per_system = 2
                else:
                    cpu_per_system = 1
            nodect = math.ceil(int(cpus) / cpu_per_system)

        # Calculate EBS Storage (storage * ebs_price * sim_time_in_secs / (walltime_seconds * 30 days) * number of nodes
        sim_cost["scratch_size"] = (
            f"{(scratch_size * EBS_GP3_STORAGE_BASELINE * (walltime * 3600) / (86400 * 30)) * nodect:.3f}"
        )
        sim_cost["root_size"] = (
            f"{(root_size * EBS_GP3_STORAGE_BASELINE * (walltime * 3600) / (86400 * 30)) * nodect:.3f}"
        )

        # Calculate FSx Storage (storage * fsx_price * sim_time_in_secs / (second_in_a_day * 30 days)
        sim_cost["fsx_capacity"] = (
            f"{(fsx_storage * FSX_STORAGE_BASELINE * (walltime * 3600) / (86400 * 30)):.3f}"
        )

        # Calculate Compute Price
        try:
            _compute_price = {}
            _compute_price = get_compute_pricing(instance_type=instance_type)
            if not _compute_price:
                return SocaResponse(
                    success=False,
                    message=f"Unable to retrieve price for {instance_type}",
                ).as_flask()

            if "ondemand" not in _compute_price:
                return SocaResponse(
                    success=False,
                    message=f"Unable to retrieve 'ondemand' price for {instance_type}: {_compute_price}",
                ).as_flask()

            if "reserved" not in _compute_price:
                return SocaResponse(
                    success=False,
                    message=f"Unable to retrieve 'reserved' price for {instance_type}: {_compute_price}",
                ).as_flask()

            _compute_price["on_demand_hourly_rate"] = float(
                f"{_compute_price['ondemand']:.3f}"
            )
            _compute_price["reserved_hourly_rate"] = float(
                f"{_compute_price['reserved']:.3f}"
            )
            _compute_price["nodes"] = nodect
            _compute_price["walltime"] = float(f"{walltime:.3f}")
            _compute_price["instance_type"] = instance_type
            _compute_price["estimated_on_demand_cost"] = float(
                f"{(_compute_price['ondemand'] * nodect) * walltime:.3f}"
            )
            _compute_price["estimated_reserved_cost"] = float(
                f"{(_compute_price['reserved'] * nodect) * walltime:.3f}"
            )

            sim_cost["compute"] = _compute_price
        except Exception as err:
            return SocaResponse(
                success=False,
                message=f"Unable to get compute price. Instance type may be incorrect or region name not tracked correctly? Error: {err}",
            ).as_flask()

        # Output
        sim_cost["estimated_storage_cost"] = float(
            f"{float(sim_cost['fsx_capacity']) + float(sim_cost['scratch_size']) + float(sim_cost['root_size']) :.3f}"
        )

        sim_cost["estimated_total_cost"] = float(
            f"{float(sim_cost['estimated_storage_cost']) + float(sim_cost['compute']['estimated_on_demand_cost']) :.3f}"
        )

        sim_cost["estimated_hourly_cost"] = float(
            f"{float(sim_cost['estimated_total_cost']) / float(walltime) :.3f}"
        )

        sim_cost["storage_pct"] = float(
            f"{float((sim_cost['estimated_storage_cost']) / float(sim_cost['estimated_total_cost'])) * 100 :.3f}"
            if float(sim_cost["estimated_storage_cost"]) != 0.000
            else 0
        )

        sim_cost["compute_pct"] = (
            f"{float((sim_cost['compute']['estimated_on_demand_cost']) / float(sim_cost['estimated_total_cost'])) * 100 :.3f}"
            if float(sim_cost["compute"]["estimated_on_demand_cost"]) != 0.000
            else 0
        )

        sim_cost["compute"]["cpus"] = cpus
        return SocaResponse(success=True, message=sim_cost).as_flask()
