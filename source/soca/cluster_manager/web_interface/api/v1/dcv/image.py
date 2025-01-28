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

import config
from flask_restful import Resource, reqparse
import logging
from decorators import admin_api, restricted_api, private_api
import botocore
from datetime import datetime, timezone
from models import db, AmiList
import math
from sqlalchemy import exc
from sqlalchemy.exc import SQLAlchemyError
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def get_ami_info():
    ami_info = {}
    for session_info in AmiList.query.filter_by(is_active=True).all():
        ami_info[session_info.ami_label] = session_info.ami_id
    return ami_info


class ManageImage(Resource):
    @admin_api
    def post(self):
        """
        Register a new EC2 AMI as DCV image on SOCA
        ---
        tags:
          - DCV

        parameters:
          - in: body
            name: body
            schema:
              required:
                - os
                - ami_id
                - ami_label
                - root_size
              properties:
                ami_id:
                  type: string
                  description: EC2 ID of the AMI
                os:
                  type: string
                  description: Windows or Linux
                ami_label:
                  type: string
                  description: Friendly name for your image
                root_size:
                  type: string
                  description: Minimum size of your EC2 AMI
                launch_tenancy:
                  type: string
                  description: Launch tenancy setting for the AMI. Defaults to 'default'.
                launch_host:
                  type: string
                  description: Launch host when using launch_tenancy of 'host'.


        responses:
          200:
            description: Pair of user/token is valid
          401:
            description: Invalid user/token pair
        """
        parser = reqparse.RequestParser()
        parser.add_argument("ami_id", type=str, location="form")
        parser.add_argument("os", type=str, location="form")
        parser.add_argument("ami_label", type=str, location="form")
        parser.add_argument("root_size", type=str, location="form")
        parser.add_argument("launch_tenancy", type=str, location="form")
        parser.add_argument("launch_host", type=str, location="form")

        args = parser.parse_args()
        logger.debug(f"Received ManageImage resource with args {args}")
        ami_id = args["ami_id"]
        ami_label = str(args["ami_label"])
        os = args["os"]
        launch_tenancy = str(args["launch_tenancy"])
        launch_host = str(args["launch_host"]) if "launch_host" in args else None

        # Launch Tenancy

        if not launch_tenancy:
            logger.warning("Tenancy not defined, default to default")
            launch_tenancy = "default"
            launch_host = None

        if launch_tenancy.lower() not in {"default", "dedicated", "host"}:
            return SocaError.IMAGE_REGISTER_ERROR(
                image_id=ami_id,
                image_label=ami_label,
                helper=f"Invalid launch_tenancy {launch_tenancy}, must be default, dedicated or host",
            ).as_flask()

        if ami_label.lower() == "base":
            return SocaError.IMAGE_REGISTER_ERROR(
                image_id=ami_id,
                image_label=ami_label,
                helper=f"AMI Label 'base' is restricted, Please pick a different name",
            ).as_flask()

        # Remove launch_host if we are not in host mode
        if launch_tenancy.lower() not in {"host"}:
            launch_host = None

        if args["os"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parmeter="os").as_flask()
        if args["ami_id"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parmeter="ami_id").as_flask()
        if args["ami_label"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parmeter="ami_label").as_flask()
        if args["root_size"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parmeter="root_size").as_flask()

        # TODO Move this to a config / common area
        _allowed_dcv_base_os = [
            "centos7",
            "rocky8",
            "rocky9",
            "rhel7",
            "rhel8",
            "rhel9",
            "amazonlinux2",
            "amazonlinux2023",
            "windows",
        ]
        if args.get("os").lower() not in _allowed_dcv_base_os:
            return SocaError.IMAGE_REGISTER_ERROR(
                image_id=ami_id,
                image_label=ami_label,
                helper=f"Invalid os {os}, must be one of {','.join(_allowed_dcv_base_os)}",
            ).as_flask()

        try:
            # Round up to the next integer size versus using int() or round() which can round _down_
            root_size: int = math.ceil(float(args["root_size"]))

        except ValueError:
            return SocaError.IMAGE_REGISTER_ERROR(
                image_id=ami_id,
                image_label=ami_label,
                helper=f"root_size must be a valid integer",
            ).as_flask()

        soca_labels = get_ami_info()

        # A valid/Registered AMI to SOCA?
        if ami_label not in soca_labels.keys():
            try:
                ec2_response = client_ec2.describe_images(
                    ImageIds=[ami_id],
                    Filters=[{"Name": "state", "Values": ["available"]}],
                )
            except Exception as err:
                return SocaError.AWS_API_ERROR(
                    service_name="ec2",
                    helper=f"Unable to describe AMI {ami_id} due to {err}",
                ).as_flask()

            logger.debug(f"API response - AMI {ami_id}: {ec2_response}")

            if len(ec2_response["Images"]) > 0:
                # Grab the root size from the AMI to make sure our admin-input size is at least that size.
                # This prevents situations where the admin may undersize the AMI setting.
                # The size is taken from the first (0th) EBS volume within the AMI.
                _ami_root_size: int = ec2_response["Images"][0]["BlockDeviceMappings"][
                    0
                ]["Ebs"]["VolumeSize"]

                _extra_logging: str = ""
                if _ami_root_size <= root_size:
                    logger.debug(
                        f"AMI {ami_id} root size requirement ({_ami_root_size}) is <= {root_size}"
                    )
                else:
                    logger.info(
                        f"AMI {ami_id} root size requirement ({_ami_root_size}GB) is > specified size ({root_size}GB) - Auto-adjusting to {_ami_root_size}GB"
                    )
                    _extra_logging = f"(root_size auto-adjusted to {_ami_root_size}GB)"
                    root_size = math.ceil(_ami_root_size)

                _ami_arch = ec2_response["Images"][0]["Architecture"]

                new_ami = AmiList(
                    ami_id=ami_id,
                    ami_type=os.lower(),
                    ami_label=ami_label,
                    ami_arch=_ami_arch,
                    is_active=True,
                    ami_root_disk_size=root_size,
                    launch_tenancy=launch_tenancy,
                    launch_host=launch_host,
                    created_on=datetime.now(timezone.utc),
                )

                try:
                    db.session.add(new_ami)
                    db.session.commit()
                except Exception as err:
                    return SocaError.DB_ERROR(
                        query=new_ami,
                        helper=f"Unable to add new AMI {ami_label} {ami_id} to DB due to {err}",
                    ).as_flask()

                return SocaResponse(success=True, message=f"{ami_id} registered successfully in SOCA as {ami_label} {_extra_logging}").as_flask()


            else:
                # TODO - Need to auto-register the default DCVDefaultVersion during installation?
                return SocaError.IMAGE_REGISTER_ERROR(
                    image_id=ami_id,
                    image_label=ami_label,
                    helper=f"{ami_id} is not available in AWS account. If you just created it, make sure the state of the image is 'available' on the AWS console",
                ).as_flask()

        else:
            return SocaError.IMAGE_REGISTER_ERROR(
                image_id=ami_id,
                image_label=ami_label,
                helper=f"Label {ami_label} already in use. Please enter a unique label",
            ).as_flask()

    @admin_api
    def delete(self):
        """
        Delete an EC2 AMI registered as DCV image on SOCA
        ---
        tags:
          - DCV

        parameters:
          - in: body
            name: body
            schema:
              required:
                - ami_label

              properties:
                ami_label:
                  type: string
                  description: Friendly name for your image

        responses:
          200:
            description: Pair of user/token is valid
          401:
            description: Invalid user/token pair
        """
        parser = reqparse.RequestParser()
        parser.add_argument("ami_label", type=str, location="form")

        args = parser.parse_args()
        logger.debug(f"Received AMI Delete for {args}")
        if args["ami_label"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parmeter="ami_label").as_flask()

        check_session = AmiList.query.filter_by(
            ami_label=args["ami_label"], is_active=True
        ).first()
        if check_session:
            try:
                check_session.is_active = False
                check_session.deactivated_on = datetime.now(timezone.utc)
                db.session.commit()
            except Exception as err:
                return SocaError.DB_ERROR(
                    query=check_session,
                    helper=f"Unable to deactivate image {args['ami_label']} due to {err}",
                ).as_flask()

            logger.info(f"AMI Label {args['ami_label']} deleted from SOCA")
            return SocaResponse(success=True, message=f"{args['ami_label']} deleted from SOCA").as_flask()

        else:
            return SocaError.IMAGE_DEREGISTER_ERROR(
                image_label=args["ami_label"], helper=f"{args['ami_label']} not found"
            ).as_flask()
