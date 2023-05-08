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


def all_errors(error_name, trace=False):
    error_list = {
        "LDAP_ALREADY_EXISTS": [f"Entry already up-to-date", 220],
        "LDAP_NO_SUCH_OBJECT": [f"Entry does not exist. Create it first", 221],
        "LDAP_NO_SUCH_ATTRIBUTE": [f"Attribute does not exist", 222],
        "LDAP_TYPE_OR_VALUE_EXISTS": [f"Entry already configured correctly", 223],
        "UID_ALREADY_IN_USE": [f"This UID is already in use", 224],
        "GID_ALREADY_IN_USE": [f"This GID is already in use", 225],
        "UNABLE_RETRIEVE_IDS": [
            f"Unable to retrieve LDAP IDS due to " + str(trace),
            225,
        ],
        "GROUP_DO_NOT_EXIST": [f"This LDAP group does not exist", 226],
        "NO_ACTIVE_TOKEN": [f"Could not find any active token for this user", 227],
        "IMAGE_NOT_DELETED": [f"Unable to delete image " + str(trace), 228],
        "API_KEY_NOT_DELETED": [f"Unable to deactivate key " + str(trace), 229],
        "UNABLE_TO_ADD_USER_TO_GROUP": [
            f"User/Group created but could not add user to his group {trace if trace is not False else ''}",
            230,
        ],
        "UNABLE_CREATE_HOME": [
            f"User created but unable to create HOME directory",
            231,
        ],
        "UNABLE_TO_GRANT_SUDO": [
            f"User added but unable to give admin permissions",
            232,
        ],
        "MISSING_DS_RESET_LAMBDA": [
            f"Flask could not locate SOCA_DS_RESET_PW_LAMBDA variable. Make sure you started the UI with socawebui.sh",
            233,
        ],
        "DS_PASSWORD_COMPLEXITY_ERROR": [
            f"Your password does not meet complexity requirements. Use one uppercase, one lowercase, one digit and/or one special char and cannot contains your username. 8 chars min",
            234,
        ],
        "DS_CREATED_USER_NO_PW": [f"Account created but unable to set password", 235],
        "DS_PASSWORD_USERNAME_IN_PW": [
            f"Your password cannot contains your username.",
            236,
        ],
        "DS_PASSWORD_USERNAME_IS_ADMIN": [
            f"Admin is an account restricted to ActiveDirectory Main User. Please pick a different name",
            237,
        ],
        "CLIENT_MISSING_PARAMETER": [f"Client input malformed. " + str(trace), 400],
        "CLIENT_INVALID_PARAMETER": [f"Received Invalid Client value: {trace}", 400],
        "CLIENT_OWN_RESOURCE": [f"You cannot delete your own user/group", 400],
        "CLIENT_NOT_OWNER": [f"You are not the owner of this resource", 400],
        "INVALID_EMAIL_ADDRESS": [
            f"The email address does not seems to be correct",
            400,
        ],
        "DCV_LAUNCH_ERROR": [f"Unable to start Desktop due to: {trace}", 400],
        "DCV_STOP_ERROR": [f"Unable to stop Desktop due to: {trace}", 400],
        "DCV_RESTART_ERROR": [f"Unable to restart Desktop due to: {trace}", 400],
        "DCV_MODIFY_ERROR": [f"Unable to modify Desktop due to: {trace}", 400],
        "DCV_SCHEDULE_ERROR": [
            f"Unable to modify schedule Desktop due to: {trace}",
            400,
        ],
        "IMAGE_REGISTER_ERROR": [f"Unable to register image due to: {trace}", 400],
        "IMAGE_DELETE_ERROR": [f"Unable to delete image due to: {trace}", 400],
        "IMAGE_LIST_ERROR": [f"Unable to list images due to: {trace}", 400],
        "APPLICATION_EXPORT_ERROR": [f"Unable to export image due: {trace}", 400],
        "APPLICATION_IMPORT_ERROR": [f"Unable to import image due: {trace}", 400],
        "INVALID_CREDENTIALS": [f"Invalid user credentials.", 401],
        "LDAP_SERVER_DOWN": [f"LDAP server seems to be down or unreachable", 500],
        "X-SOCA-USER_MISSING": [
            f"Unable to retrieve request owner. X-SOCA-USER must be set",
            500,
        ],
        "COULD_NOT_CREATE_GROUP": [f"Unable to create LDAP group. " + str(trace), 500],
        "UNICODE_ERROR": [f"Unicode error. {trace} ", 500],
    }

    if error_name in error_list.keys():
        return {"success": False, "message": error_list[error_name][0]}, error_list[
            error_name
        ][1]
    else:
        return {
            "success": False,
            "message": "Unknown error caused by: " + str(trace),
        }, 500
