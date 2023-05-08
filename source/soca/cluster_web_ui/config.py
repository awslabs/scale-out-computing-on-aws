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
import secrets
from cryptography.fernet import Fernet
from botocore import config as botocore_config
import read_secretmanager

basedir = os.path.abspath(os.path.dirname(__file__))


def boto_extra_config():
    aws_solution_user_agent = {"user_agent_extra": "AwsSolution/SO0072/2.7.4"}
    return botocore_config.Config(**aws_solution_user_agent)


class Config(object):
    soca_config = read_secretmanager.get_soca_configuration()

    # APP
    DEBUG = False
    USE_PERMANENT_SESSION = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_TYPE = "sqlalchemy"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_SQLALCHEMY_TABLE = "flask_sessions"
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "db.sqlite")
    SECRET_KEY = os.environ["SOCA_FLASK_SECRET_KEY"]
    API_ROOT_KEY = os.environ["SOCA_FLASK_API_ROOT_KEY"]
    SOCA_DATA_SHARING_SYMMETRIC_KEY = os.environ["SOCA_FLASK_FERNET_KEY"]
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
    MAX_UPLOAD_TIMEOUT = 1800000  # 30 minutes
    ALLOW_DOWNLOAD_FROM_PORTAL = (
        True  # Give user ability to download files from the web portal
    )
    MAX_SIZE_ONLINE_PREVIEW = 150000000  # in bytes (150mb by default), maximum size of file that can be visualized via the web editor
    MAX_ARCHIVE_SIZE = 150000000  # in bytes (150mb by default), maximum size of archive generated when downloading multiple files at once
    DAILY_BACKUP_COUNT = 15  # Keep 15 latest daily backups
    KIBANA_JOB_INDEX = "soca-jobs*"  # Default index to look for /my_activity. Change it something more specific if using more than 1 index with name ~ "job*"

    # UWSGI SETTINGS
    FLASK_HOST = "127.0.0.1"
    FLASK_PROTOCOL = "https://"
    FLASK_PORT = "8443"
    FLASK_ENDPOINT = FLASK_PROTOCOL + FLASK_HOST + ":" + FLASK_PORT

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
    # 2022.2
    DCV_WINDOWS_AMI = {
        "graphics-amd": {
            "us-east-1": "ami-079b1289945e31397",
            "us-east-2": "ami-0e249f5d39f91f2f4",
            "ca-central-1": "ami-04a285bea28b03aa8",
            "us-west-2": "ami-027c182712886555f",
            "eu-west-1": "ami-003e92b402c37b8c3",
            "eu-west-2": "ami-0cc01d6ede331b397",
            "eu-central-1": "ami-0f938ea3b438c5264",
            "ap-northeast-1": "ami-0b3b14d67fcb9123e",
        },
        "graphics": {
            # Nvidia
            "us-east-1": "ami-0cf41c11d3fa97da5",
            "us-east-2": "ami-0268f01e8fb7e1af3",
            "ca-central-1": "ami-0486e50471fb25a3a",
            "us-west-1": "ami-0fc3b5bb5928ea710",
            "us-west-2": "ami-0c10cec74382ca9e0",
            "eu-west-1": "ami-0ff1e68d6e1607215",
            "eu-west-2": "ami-0d53b26481b70af89",
            "eu-west-3": "ami-0ad001e4894b1a0ca",
            "eu-central-1": "ami-08fde2d58bdaec1ce",
            "eu-north-1": "ami-03a287c0eb445490a",
            "eu-south-1": "ami-081d0182cefd9aa2f",
            "ap-northeast-1": "ami-0eb109172d3113ded",
            "ap-northeast-2": "ami-0494f802e96e6c82e",
            "ap-southeast-1": "ami-0468047f972420f58",
            "ap-southeast-2": "ami-00a5512963d78992e",
            "ap-south-1": "ami-044352a08ae6abf8b",
            "sa-east-1": "ami-08349b52d65f189d2",
            "af-south-1": "ami-0fa3212b891ec5229",
            "me-south-1": "ami-0077ceea73246a807"
        },
        "non-graphics": {
            "us-east-1": "ami-08b47fddb4ba746b1",
            "us-east-2": "ami-03d5e7631c44bb64f",
            "ca-central-1": "ami-01bd9c8d8fe091ec5",
            "us-west-1": "ami-0fcb6f452b987831b",
            "us-west-2": "ami-04fcdb0e74a7c1ffe",
            "eu-west-1": "ami-02152a6180c33a271",
            "eu-west-2": "ami-09fb2e1db38f28409",
            "eu-west-3": "ami-0696004a126982b82",
            "eu-central-1": "ami-0b7c04cddaf0d0657",
            "eu-north-1": "ami-0789d6077a6611769",
            "eu-south-1": "ami-022931dd5a86492f6",
            "ap-northeast-1": "ami-0dbfaf3f7ada2814f",
            "ap-northeast-2": "ami-05d14fc8790162b90c",
            "ap-southeast-1": "ami-025c0ea2676ef21b8",
            "ap-southeast-2": "ami-00b3f8fc29827f368",
            "ap-south-1": "ami-0c23b9f35ff99c1a1",
            "sa-east-1": "ami-027cc0155ff1d1a7a",
            "af-south-1": "ami-046ee35e0ed17612a",
            "me-south-1": "ami-0790eff3583c6b51b"
        },
    }

    SOCA_AUTH_PROVIDER = os.environ.get("SOCA_AUTH_PROVIDER")
    if SOCA_AUTH_PROVIDER == "openldap":
        # LDAP
        LDAP_HOST = soca_config["LdapHost"]
        LDAP_BASE_DN = soca_config["LdapBase"]
        LDAP_ADMIN_PASSWORD_FILE = "/root/OpenLdapAdminPassword.txt"
        LDAP_ADMIN_USERNAME_FILE = "/root/OpenLdapAdminUsername.txt"
        ROOT_DN = (
            "CN="
            + open(LDAP_ADMIN_USERNAME_FILE, "r").read().rstrip().lstrip()
            + ","
            + LDAP_BASE_DN
        )
        ROOT_PW = open(LDAP_ADMIN_PASSWORD_FILE, "r").read().rstrip().lstrip()
    else:
        DOMAIN_NAME = soca_config["DSDomainName"]
        DIRECTORY_SERVICE_ID = soca_config["DSDirectoryId"]
        ROOT_USER = soca_config["DSDomainAdminUsername"]
        ROOT_PW = soca_config["DSDomainAdminPassword"]
        LDAP_BASE = soca_config["DSDomainBase"]
        NETBIOS = soca_config["DSDomainNetbios"]
        DIRECTORY_SERVICE_RESET_LAMBDA_ARN = soca_config["DSResetLambdaFunctionArn"]
        SUDOERS_GROUP = "AWS Delegated Administrators"
        SUDOERS_GROUP_DN = f"CN={SUDOERS_GROUP},OU=AWS Delegated Groups,{LDAP_BASE}"
        # With AD, user and group share the same OU (Domain Users).
        # To identify group/user, group associated to "user" will be named "user<GROUP_NAME_SUFFIX>"
    GROUP_NAME_SUFFIX = "socagroup"

    # PBS
    PBS_QSTAT = "/opt/pbs/bin/qstat"
    PBS_QDEL = "/opt/pbs/bin/qdel"
    PBS_QSUB = "/opt/pbs/bin/qsub"
    PBS_QMGR = "/opt/pbs/bin/qmgr"

    # SSH
    SSH_PRIVATE_KEY_LOCATION = "tmp/ssh"


app_config = Config()
