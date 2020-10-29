

def all_errors(error_name, trace=False):
    error_list = {
        "LDAP_ALREADY_EXISTS": ["Entry already up-to-date", 220],
        "LDAP_NO_SUCH_OBJECT": ["Entry does not exist. Create it first", 221],
        "LDAP_NO_SUCH_ATTRIBUTE": ["Attribute does not exist", 222],
        "LDAP_TYPE_OR_VALUE_EXISTS": ["Entry already configured correctly", 223],
        "UID_ALREADY_IN_USE": ["This UID is already in use", 224],
        "GID_ALREADY_IN_USE": ["This GID is already in use", 225],
        "UNABLE_RETRIEVE_IDS": ["Unable to retrieve LDAP IDS due to " + str(trace), 225],
        "GROUP_DO_NOT_EXIST": ["This LDAP group does not exist", 226],
        "NO_ACTIVE_TOKEN": ["Could not find any active token for this user", 227],
        "IMAGE_NOT_DELETED": ["Unable to delete image " + str(trace), 228],
        "CLIENT_MISSING_PARAMETER": ["Client input malformed. " + str(trace), 400],
        "CLIENT_OWN_RESOURCE": ["You cannot delete your own user/group", 400],
        "CLIENT_NOT_OWNER": ["You are not the owner of this resource", 400],
        "INVALID_EMAIL_ADDRESS": ["The email address does not seems to be correct", 400],
        "INVALID_CREDENTIALS": ["Invalid user credentials", 401],
        "LDAP_SERVER_DOWN": ["LDAP server seems to be down or unreachable", 500],
        "X-SOCA-USER_MISSING": ["Unable to retrieve request owner. X-SOCA-USER must be set", 500],
        "COULD_NOT_CREATE_GROUP": ["Unable to create LDAP group. " + str(trace), 500],
        "UNICODE_ERROR": ["Unicode error. " +str(trace), 500],

    }

    if error_name in error_list.keys():
        return {"success": False, "message": error_list[error_name][0]}, error_list[error_name][1]
    else:
        return {"success": False, "message": "Unknown error caused by: " + str(trace)}, 500
