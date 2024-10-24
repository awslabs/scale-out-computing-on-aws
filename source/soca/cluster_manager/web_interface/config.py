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

import os
from datetime import timedelta
import utils.cache as utils_cache
from utils.aws.secrets_manager import SocaSecret
from utils.aws.ssm_parameter_store import SocaConfig
import sys

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    cache_config = utils_cache.get_cache_config(is_admin=True)
    # APP
    DEBUG = False
    USE_PERMANENT_SESSION = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "db.sqlite")
    if cache_config.get("cache_info").get("enabled"):
        SESSION_TYPE = "redis"
        SESSION_REDIS = cache_config.get("cache_client")
    else:
        SESSION_TYPE = "sqlalchemy"
    SECRET_KEY = os.environ.get("SOCA_FLASK_SECRET_KEY", False)
    API_ROOT_KEY = os.environ.get("SOCA_FLASK_API_ROOT_KEY", False)
    SOCA_DATA_SHARING_SYMMETRIC_KEY = os.environ.get("SOCA_FLASK_FERNET_KEY", False)
    TIMEZONE = "UTC"  # Change to match your local timezone if needed. See https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for all TZ

    # WEB
    APPS_LOCATION = "/apps/"
    USER_HOME = "/data/home"
    CHROOT_USER = False  # if True, user can only access their $HOME directory (aka: USER_HOME/<user>)
    PATH_TO_RESTRICT = [
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/local",
        "/media",
        "/opt",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/tmp",
        "/usr",  # nosec
        "/var",
    ]  # List of folders not accessible via the web ui
    DEFAULT_CACHE_TIME = 120  # 2 minutes. Change this value to optimize performance in case you have a large number of concurrent user
    MAX_UPLOAD_FILE = 5120  # 5 GB
    MAX_UPLOAD_TIMEOUT = 1_800_000  # 30 minutes
    ALLOW_DOWNLOAD_FROM_PORTAL = (
        True  # Give user ability to download files from the web portal
    )
    MAX_SIZE_ONLINE_PREVIEW = 150_000_000  # in bytes (150mb by default), maximum size of file that can be visualized via the web editor
    MAX_ARCHIVE_SIZE = 150_000_000  # in bytes (150mb by default), maximum size of archive generated when downloading multiple files at once
    LOG_DAILY_BACKUP_COUNT = 31  # Keep 15 latest daily backups
    KIBANA_JOB_INDEX = "soca-jobs*"  # Default index to look for /my_activity. Change it something more specific if using more than 1 index with name ~ "job*"

    # UWSGI SETTINGS
    FLASK_HOST = "127.0.0.1"
    FLASK_PROTOCOL = "https://"
    FLASK_PORT = "8443"
    FLASK_ENDPOINT = f"{FLASK_PROTOCOL}{FLASK_HOST}:{FLASK_PORT}"

    # COGNITO
    ENABLE_SSO = False
    COGNITO_OAUTH_AUTHORIZE_ENDPOINT = "https://<YOUR_COGNITO_DOMAIN_NAME>.auth.<YOUR_REGION>.amazoncognito.com/oauth2/authorize"
    COGNITO_OAUTH_TOKEN_ENDPOINT = "https://<YOUR_COGNITO_DOMAIN_NAME>.auth.<YOUR_REGION>.amazoncognito.com/oauth2/token"
    COGNITO_JWS_KEYS_ENDPOINT = "https://cognito-idp.<YOUR_REGION>.amazonaws.com/<YOUR_REGION>_<YOUR_ID>/.well-known/jwks.json"
    COGNITO_APP_SECRET = "<YOUR_APP_SECRET>"
    COGNITO_APP_ID = "<YOUR_APP_ID>"
    COGNITO_ROOT_URL = "<YOUR_WEB_URL>"
    COGNITO_CALLBACK_URL = "<YOUR_CALLBACK_URL>"

    # DCV General
    DCV_AUTH_DIR = "/var/run/dcvsimpleextauth"
    DCV_SIMPLE_AUTH = "/usr/libexec/dcvsimpleextauth.py"
    DCV_SESSION_LOCATION = "tmp/dcv_sessions"
    DCV_FORCE_INSTANCE_HIBERNATE_SUPPORT = (
        False  # If True, users can only provision instances that support hibernation
    )
    DCV_TOKEN_SYMMETRIC_KEY = os.environ[
        "SOCA_DCV_TOKEN_SYMMETRIC_KEY"
    ]  # used to encrypt/decrypt and validate DCV session auth
    DCV_RESTRICTED_INSTANCE_TYPE = [
        "metal",
        "nano",
        "micro",
        "p3",
        "p2",
        "p3dn",
        "g2",
    ]  # This instance type won't be visible on the dropdown menu
    DCV_IDLE_CPU_THRESHOLD = 15  # SOCA will NOT hibernate/stop an instance if current CPU usage % is over this value

    # DCV Linux
    DCV_LINUX_SESSION_COUNT = 4
    DCV_LINUX_ALLOW_INSTANCE_CHANGE = (
        True  # Allow user to change their instance type if their DCV session is stopped
    )
    DCV_LINUX_HIBERNATE_IDLE_SESSION = 1  # In hours. Linux DCV sessions will be hibernated to save cost if there is no active connection within the time specified. 0 to disable
    DCV_LINUX_STOP_IDLE_SESSION = 1  # In hours. Linux DCV sessions will be stopped to save cost if there is no active connection within the time specified. 0 to disable
    DCV_LINUX_TERMINATE_STOPPED_SESSION = 0  # In hours. Stopped Linux DCV will be permanently terminated if user won't restart it within the time specified. 0 to disable
    DCV_LINUX_DEFAULT_SCHEDULE = {
        "weekdays": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60) mon-fri
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60) mon-fri
        },
        "weekend": {
            "start": 0,  # Default Schedule - Stopped by default sat-sun
            "stop": 0,  # Default Schedule - Stopped by default sat-sun
        },
    }

    # DCV Windows
    DCV_WINDOWS_SESSION_COUNT = 4
    DCV_WINDOWS_ALLOW_INSTANCE_CHANGE = (
        True  # Allow user to change their instance type if their DCV session is stopped
    )
    DCV_WINDOWS_HIBERNATE_IDLE_SESSION = 1  # In hours. Windows DCV sessions will be hibernated to save cost if there is no active connection within the time specified. 0 to disable
    DCV_WINDOWS_STOP_IDLE_SESSION = 1  # In hours. Windows DCV sessions will be stopped to save cost if there is no active connection within the time specified. 0 to disable
    DCV_WINDOWS_TERMINATE_STOPPED_SESSION = 0  # In hours. Stopped Windows DCV will be permanently terminated if user won't restart it within the time specified. 0 to disable
    DCV_WINDOWS_AUTOLOGON = True  # enable or disable autologon. If disabled user will have to manually input Windows password
    DCV_WINDOWS_DEFAULT_SCHEDULE = {
        "weekdays": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60) mon-fri
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60) mon-fri
        },
        "weekend": {
            "start": 0,  # Default Schedule - Stopped by default sat-sun
            "stop": 0,  # Default Schedule - Stopped by default sat-sun
        },
    }
    #
    # DCV server version to use for eVDI as fallback
    # NOTE: While the download page version syntax is yyyy.a-b , this format must be yyyy.a.b to match how the
    # the AMI strings are stored / searched. So '2023.1-16388' becomes '2023.1.16388' (dash turned to a dot)
    DCV_AMI_VERSION = (
        SocaConfig(key="/configuration/DCVDefaultVersion").get_value().get("message")
    )

    # User Directory
    DIRECTORY_AUTH_PROVIDER = SocaConfig(key="/configuration/UserDirectory/provider").get_value().get("message")
    DIRECTORY_GROUP_SEARCH_BASE = SocaConfig(key="/configuration/UserDirectory/group_search_base").get_value().get("message")
    DIRECTORY_PEOPLE_SEARCH_BASE = SocaConfig(key="/configuration/UserDirectory/people_search_base").get_value().get("message")
    DIRECTORY_ADMIN_SEARCH_BASE = SocaConfig(key="/configuration/UserDirectory/admins_search_base").get_value().get("message")
    DIRECTORY_BASE_DN = SocaConfig(key="/configuration/UserDirectory/domain_base").get_value().get("message")
    DIRECTORY_DOMAIN_NAME = SocaConfig(key="/configuration/UserDirectory/domain_name").get_value().get("message")
    DIRECTORY_SERVICE_ID = SocaConfig(key="/configuration/UserDirectory/ad_aws_directory_service_id").get_value().get("message")
    DIRECTORY_NETBIOS = SocaConfig(key="/configuration/UserDirectory/short_name").get_value().get("message")
    DIRECTORY_ENDPOINT = SocaConfig(key="/configuration/UserDirectory/endpoint").get_value().get("message")
    DIRECTORY_SERVICE_RESET_LAMBDA_ARN = SocaConfig(key="/configuration/UserDirectory/ad_aws_lambda_reset_password").get_value().get("message")
    # To identify group/user, group associated to "user" will be named "user<GROUP_NAME_SUFFIX>"
    DIRECTORY_GROUP_NAME_SUFFIX = "socagroup"
    # Fetch Directory service account
    _soca_ds_service_account_secret = SocaConfig(key="/configuration/UserDirectory/service_account_secret_arn").get_value().get("message")
    DIRECTORY_ADMIN_USER_SECRET = SocaSecret(secret_id_prefix="", secret_id=_soca_ds_service_account_secret).get_secret()
    if not DIRECTORY_ADMIN_USER_SECRET.success:
        print("Unable to retrieve Directory credentials.")
        sys.exit(1)

    # PBS
    PBS_QSTAT = "/opt/pbs/bin/qstat"
    PBS_QDEL = "/opt/pbs/bin/qdel"
    PBS_QSUB = "/opt/pbs/bin/qsub"
    PBS_QMGR = "/opt/pbs/bin/qmgr"

    # SSH
    SSH_PRIVATE_KEY_LOCATION = "tmp/ssh"


app_config = Config()
