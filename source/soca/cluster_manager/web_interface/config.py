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
from utils.cast import SocaCastEngine
import sys

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    cache_config = utils_cache.get_cache_config(is_admin=True)
    # APP
    DEBUG = False
    USE_PERMANENT_SESSION = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "db.sqlite")
    _cache_enabled = SocaCastEngine(
        data=cache_config.get("cache_info").get("enabled")
    ).cast_as(bool)
    # Validate if cache_info.enabled is a valid bool and if the value is also True
    if _cache_enabled.get("success") is True and _cache_enabled.get("message") is True:
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

    # DCV Linux
    DCV_LINUX_SESSION_COUNT = 4
    DCV_LINUX_ALLOW_INSTANCE_CHANGE = (
        True  # Allow user to change their instance type if their DCV session is stopped
    )
    DCV_LINUX_STOP_IDLE_SESSION = 2  # In hours. Linux DCV sessions will be stopped/hibernated to save cost if there is no active connection within the time specified. 0 to disable
    DCV_LINUX_TERMINATE_STOPPED_SESSION = 0  # In hours. Stopped Linux DCV will be permanently terminated if user/schedule won't restart it within the time specified. 0 to disable

    # DCV Windows
    DCV_WINDOWS_SESSION_COUNT = 4
    DCV_WINDOWS_ALLOW_INSTANCE_CHANGE = (
        True  # Allow user to change their instance type if their DCV session is stopped
    )
    DCV_WINDOWS_STOP_IDLE_SESSION = 2  # In hours. Windows DCV sessions will be stopped/Hibernated to save cost if there is no active connection within the time specified. 0 to disable
    DCV_WINDOWS_TERMINATE_STOPPED_SESSION = 0  # In hours. Stopped Windows DCV will be permanently terminated if user/schedule won't restart it within the time specified. 0 to disable

    DCV_WINDOWS_AUTOLOGON = True  # enable or disable autologon. If disabled user will have to manually input Windows password

    # Grace Period
    # - Will not stop a desktop if it was started within the grace period
    # - Will not start a desktop if it was stopped within  the grace period
    # In other word, even if your schedule is stopped all day, but you manually start your desktop, it will stays up and running for X hours)
    DCV_SCHEDULE_GRACE_PERIOD_IN_HOURS = 2

    DCV_FORCE_INSTANCE_HIBERNATE_SUPPORT = (
        False  # If True, users can only provision instances that support hibernation
    )
    DCV_TOKEN_SYMMETRIC_KEY = os.environ[
        "SOCA_DCV_TOKEN_SYMMETRIC_KEY"
    ]  # used to encrypt/decrypt and validate DCV session auth

    DCV_IDLE_CPU_THRESHOLD = 15  # SOCA will NOT hibernate/stop an instance if current CPU usage % is over this value

    DCV_VERIFY_SESSION_HEALTH = True  # if set to True, scheduled_tasks/virtual_desktops/session_state_watcher will try to validate if the DCV Session is correctly running

    DCV_ALLOW_DEFAULT_SCHEDULE_UPDATE = (
        True  # Whether users can override the defualt schedule
    )

    DCV_DEFAULT_SCHEDULE = {
        "monday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "tuesday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "wednesday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "thursday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "friday": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60)
            "stop": 1140,  # Default Schedule - Stop if idle after 7 PM (19*60)
        },
        "saturday": {
            "start": 0,  # Default Schedule - Stopped all day
            "stop": 0,  # Default Schedule - Stopped all day
        },
        "sunday": {
            "start": 0,  # Default Schedule - Stopped all day
            "stop": 0,  # Default Schedule - Stopped all day
        },
    }

    DCV_BASE_OS = {
        "ubuntu2404": {
            "family": "linux",
            "friendly_name": "Ubuntu 24.04",
            "visible": True,
        },
        "ubuntu2204": {
            "family": "linux",
            "friendly_name": "Ubuntu 22.04",
            "visible": True,
        },
        "amazonlinux2": {
            "family": "linux",
            "friendly_name": "Amazon Linux 2",
            "visible": True,
        },
        "rocky9": {
            "family": "linux",
            "friendly_name": "Rocky Linux 9",
            "visible": True,
        },
        "rocky8": {
            "family": "linux",
            "friendly_name": "Rocky Linux 8",
            "visible": True,
        },
        "rhel9": {
            "family": "linux",
            "friendly_name": "Red Hat Enterprise Linux 9",
            "visible": True,
        },
        "rhel8": {
            "family": "linux",
            "friendly_name": "Red Hat Enterprise Linux 8",
            "visible": True,
        },
        "rhel7": {
            "family": "linux",
            "friendly_name": "Red Hat Enterprise Linux 7",
            "visible": False,
        },
        "centos7": {"family": "linux", "friendly_name": "CentOS 7", "visible": False},
        "windows2019": {
            "family": "windows",
            "friendly_name": "Windows Server 2019",
            "visible": True,
        },
        "windows2022": {
            "family": "windows",
            "friendly_name": "Windows Server 2022",
            "visible": True,
        },
        "windows2025": {
            "family": "windows",
            "friendly_name": "Windows Server 2025",
            "visible": True,
        },
    }

    # Default Instance Type for each AMI
    DCV_DEFAULT_AMI_INSTANCE_TYPES = (
        SocaConfig(key="/configuration/DCVAllowedInstances")
        .get_value(return_as=list)
        .get("message")
    )

    # User Directory
    DIRECTORY_AUTH_PROVIDER = (
        SocaConfig(key="/configuration/UserDirectory/provider")
        .get_value()
        .get("message")
    )
    DIRECTORY_GROUP_SEARCH_BASE = (
        SocaConfig(key="/configuration/UserDirectory/group_search_base")
        .get_value()
        .get("message")
    )
    DIRECTORY_PEOPLE_SEARCH_BASE = (
        SocaConfig(key="/configuration/UserDirectory/people_search_base")
        .get_value()
        .get("message")
    )
    DIRECTORY_ADMIN_SEARCH_BASE = (
        SocaConfig(key="/configuration/UserDirectory/admins_search_base")
        .get_value()
        .get("message")
    )
    DIRECTORY_BASE_DN = (
        SocaConfig(key="/configuration/UserDirectory/domain_base")
        .get_value()
        .get("message")
    )
    DIRECTORY_DOMAIN_NAME = (
        SocaConfig(key="/configuration/UserDirectory/domain_name")
        .get_value()
        .get("message")
    )
    DIRECTORY_SERVICE_ID = (
        SocaConfig(key="/configuration/UserDirectory/ad_aws_directory_service_id")
        .get_value()
        .get("message")
    )
    DIRECTORY_NETBIOS = (
        SocaConfig(key="/configuration/UserDirectory/short_name")
        .get_value()
        .get("message")
    )
    DIRECTORY_ENDPOINT = (
        SocaConfig(key="/configuration/UserDirectory/endpoint")
        .get_value()
        .get("message")
    )

    # To identify group/user, group associated to "user" will be named "user<GROUP_NAME_SUFFIX>"
    DIRECTORY_GROUP_NAME_SUFFIX = "socagroup"
    # Fetch Directory service account
    _soca_ds_service_account_secret = (
        SocaConfig(key="/configuration/UserDirectory/service_account_secret_arn")
        .get_value()
        .get("message")
    )
    DIRECTORY_ADMIN_USER_SECRET = SocaSecret(
        secret_id_prefix="", secret_id=_soca_ds_service_account_secret
    ).get_secret()
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

    # Amazon Q for Business
    # Add your Amazon Q for Business URL (ex: https://t5i9puav.chat.qbusiness.us-west-2.on.aws/) to display Amazon Q logo in the horizontal bar
    AMAZON_Q_BUSINESS_URL = False


app_config = Config()
