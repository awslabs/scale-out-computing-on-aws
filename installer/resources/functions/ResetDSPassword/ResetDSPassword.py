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

"""
This lambda is used to reset user password when using AD
This uses a separate IAM role as we do not want to give ds:ResetUserPassword permission to either scheduler or compute node role
AD Password Reset can be integrated via python-ldap if the customer deploy LdapS (AD won't let you update an LDAP password if you do not use LDAPS)
"""

import boto3


def lambda_handler(event, context):
    directory_service = boto3.client("ds")
    required_params = ["DirectoryServiceId", "Username", "Password"]
    data = {}
    for param in required_params:
        if param not in event.keys():
            return f"{param} is missing"
        else:
            data[param] = event[param]

    directory_service_id = data["DirectoryServiceId"]
    username = data["Username"]
    new_password = data["Password"]
    if username.lower() in new_password.lower():
        return "PasswordCannotContainsUsername"
    try:
        pw_reset_request = directory_service.reset_user_password(
            DirectoryId=directory_service_id,
            UserName=username,
            NewPassword=new_password,
        )
        return "Success"
    except directory_service.exceptions.InvalidPasswordException:
        return "InvalidPasswordException"
    except directory_service.exceptions.UserDoesNotExistException:
        return "UserDoesNotExistException"
    except Exception as e:
        return e
