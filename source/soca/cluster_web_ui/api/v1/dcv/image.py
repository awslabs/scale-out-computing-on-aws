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
import datetime
from models import db, AmiList
import boto3
import errors
from sqlalchemy import exc
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger("api")
session = boto3.session.Session()
aws_region = session.region_name
ec2_client = boto3.client('ec2', aws_region, config=config.boto_extra_config())


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


        responses:
          200:
            description: Pair of user/token is valid
          401:
            description: Invalid user/token pair
        """
        parser = reqparse.RequestParser()
        parser.add_argument('ami_id', type=str, location='form')
        parser.add_argument('os', type=str, location='form')
        parser.add_argument('ami_label', type=str, location='form')
        parser.add_argument('root_size', type=str, location='form')

        args = parser.parse_args()
        ami_id = args["ami_id"]
        ami_label = str(args["ami_label"])
        os = args["os"]

        if args["os"] is None or args["ami_label"] is None or args["ami_id"] is None or args["root_size"] is None:
            return errors.all_errors('CLIENT_MISSING_PARAMETER', "os (str), ami_id (str), ami_label (str) and root_size (str)  are required.")

        if args["os"].lower() not in ["centos7", "rhel7", "amazonlinux2", "windows"]:
            return errors.all_errors('CLIENT_MISSING_PARAMETER', "os must be centos7, rhel7, amazonlinux2, or windows")

        try:
            root_size = int(args["root_size"])
        except ValueError:
            return errors.all_errors('IMAGE_REGISTER_ERROR', f"{root_size} must be a valid integer")
        soca_labels = get_ami_info()

        # Register AMI to SOCA
        if ami_label not in soca_labels.keys():
            try:
                ec2_response = ec2_client.describe_images(ImageIds=[ami_id],
                                                          Filters=[{'Name': 'state', 'Values': ['available']}])
                if (len(ec2_response["Images"]) != 0):
                    new_ami = AmiList(ami_id=ami_id,
                                      ami_type=os.lower(),
                                      ami_label=ami_label,
                                      is_active=True,
                                      ami_root_disk_size=root_size,
                                      created_on=datetime.datetime.utcnow())
                    try:
                        db.session.add(new_ami)
                        db.session.commit()
                        return {"success": True, "message": f"{ami_id} registered successfully in SOCA as {ami_label}"}, 200
                    except SQLAlchemyError as e:
                        db.session.rollback()
                        logger.error(f"Failed Creating AMI {ami_label} {ami_id} {e}")
                        return errors.all_errors('IMAGE_REGISTER_ERROR', f"{ami_id} registration not successful")
                else:
                    logger.error(f"{ami_id} is not available in AWS account")
                    return errors.all_errors('IMAGE_REGISTER_ERROR', f"{ami_id} is not available in AWS account. If you just created it, make sure the state of the image is 'available' on the AWS console")
            except botocore.exceptions.ClientError as error:
                logger.error(f"Failed Creating AMI {ami_label} {ami_id} {error}")
                return errors.all_errors('IMAGE_REGISTER_ERROR', f"{ami_id} Couldn't locate {ami_id} in AWS account. Make sure you do have permission to view it")
        else:
            logger.error(f"Label already in use {ami_label}")
            return errors.all_errors('IMAGE_REGISTER_ERROR', f"Label {ami_label} already in use. Please enter a unique label")

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
        parser.add_argument('ami_label', type=str, location='form')

        args = parser.parse_args()
        if args["ami_label"] is None:
            return errors.all_errors('CLIENT_MISSING_PARAMETER', "ami_label (str) is required.")

        check_session = AmiList.query.filter_by(ami_label=args["ami_label"], is_active=True).first()
        if check_session:
            check_session.is_active = False
            check_session.deactivated_on = datetime.datetime.utcnow()
            try:
                db.session.commit()
                logger.info(f"AMI Label {args['ami_label']} deleted from SOCA")
                return {"success": True, "message": f"{args['ami_label']} deleted from SOCA successfully"}, 200
            except exc.SQLAlchemyError as e:
                db.session.rollback()
                logger.error(f"AMI Label {args['ami_label']} delete failed {e}")
                return errors.all_errors('IMAGE_DELETE_ERROR', f"{args['ami_label']} could not have been deleted because of {e}")
        else:
            return errors.all_errors('IMAGE_DELETE_ERROR', f"{args['ami_label']} could not be found")