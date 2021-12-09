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
    aws_solution_user_agent = {"user_agent_extra": "AwsSolution/SO0072/v2.7.0"}
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
    PATH_TO_RESTRICT = ['/bin', '/boot', '/dev', '/etc', '/home', '/lib', '/lib64', '/local',
                        '/media', '/opt', '/proc', '/root', '/run', '/sbin', '/srv', '/sys', '/tmp', '/usr', # nosec
                        '/var']  # List of folders not accessible via the web ui
    DEFAULT_CACHE_TIME = 120  # 2 minutes. Change this value to optimize performance in case you have a large number of concurrent user
    MAX_UPLOAD_FILE = 5120  # 5 GB
    MAX_UPLOAD_TIMEOUT = 1800000  # 30 minutes
    ALLOW_DOWNLOAD_FROM_PORTAL = True  # Give user ability to download files from the web portal
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
    DCV_FORCE_INSTANCE_HIBERNATE_SUPPORT = False  # If True, users can only provision instances that support hibernation
    DCV_TOKEN_SYMMETRIC_KEY = os.environ["SOCA_DCV_TOKEN_SYMMETRIC_KEY"]  # used to encrypt/decrypt and validate DCV session auth
    DCV_RESTRICTED_INSTANCE_TYPE = ['metal', 'nano', 'micro', 'p3', 'p2', 'p3dn', 'g2']  # This instance type won't be visible on the dropdown menu
    DCV_IDLE_CPU_THRESHOLD = 15  # SOCA will NOT hibernate/stop an instance if current CPU usage % is over this value

    # DCV Linux
    DCV_LINUX_SESSION_COUNT = 4
    DCV_LINUX_ALLOW_INSTANCE_CHANGE = True  # Allow user to change their instance type if their DCV session is stopped
    DCV_LINUX_HIBERNATE_IDLE_SESSION = 1  # In hours. Linux DCV sessions will be hibernated to save cost if there is no active connection within the time specified. 0 to disable
    DCV_LINUX_STOP_IDLE_SESSION = 1  # In hours. Linux DCV sessions will be stopped to save cost if there is no active connection within the time specified. 0 to disable
    DCV_LINUX_TERMINATE_STOPPED_SESSION = 0  # In hours. Stopped Linux DCV will be permanently terminated if user won't restart it within the time specified. 0 to disable
    DCV_LINUX_DEFAULT_SCHEDULE = {
        "weekdays": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60) mon-fri
            "stop": 1140  # Default Schedule - Stop if idle after 7 PM (19*60) mon-fri
        },
        "weekend": {
            "start": 0,  # Default Schedule - Stopped by default sat-sun
            "stop": 0  # Default Schedule - Stopped by default sat-sun
        }
    }


    # DCV Windows
    DCV_WINDOWS_SESSION_COUNT = 4
    DCV_WINDOWS_ALLOW_INSTANCE_CHANGE = True  # Allow user to change their instance type if their DCV session is stopped
    DCV_WINDOWS_HIBERNATE_IDLE_SESSION = 1  # In hours. Windows DCV sessions will be hibernated to save cost if there is no active connection within the time specified. 0 to disable
    DCV_WINDOWS_STOP_IDLE_SESSION = 1  # In hours. Windows DCV sessions will be stopped to save cost if there is no active connection within the time specified. 0 to disable
    DCV_WINDOWS_TERMINATE_STOPPED_SESSION = 0  # In hours. Stopped Windows DCV will be permanently terminated if user won't restart it within the time specified. 0 to disable
    DCV_WINDOWS_AUTOLOGON = True  # enable or disable autologon. If disabled user will have to manually input Windows password
    DCV_WINDOWS_DEFAULT_SCHEDULE = {
        "weekdays": {
            "start": 480,  # Default Schedule - Start 8 AM (8*60) mon-fri
            "stop": 1140  # Default Schedule - Stop if idle after 7 PM (19*60) mon-fri
        },
        "weekend": {
            "start": 0,  # Default Schedule - Stopped by default sat-sun
            "stop": 0  # Default Schedule - Stopped by default sat-sun
        }
    }
    DCV_WINDOWS_AMI = {
        "graphics-amd": {
            'us-east-1': 'ami-09e9fc6b0563179e0',
            'ca-central-1': 'ami-02ce5abc7648ae028',
             'us-east-2': 'ami-0e9dffe211d55ea3d',
             'us-west-2': 'ami-0ca9facae744b755d',
             'eu-west-1': 'ami-0b79b4e3a40bdf60e',
             'eu-west-2': 'ami-049344b657f4fb45c',
             'eu-central-1': 'ami-01f877801cd06f23f',
             'ap-northeast-1': 'ami-0f73f5c42d0a2a659'
        },
        "graphics": {
            # Nvidia
            'us-east-1': 'ami-0feb4b3151fb93b8e',
             'ca-central-1': 'ami-01a3418587fbf46cb',
             'us-east-2': 'ami-08dbaa5a7a0d66dd8',
             'us-west-1': 'ami-044ba431fff097d34',
             'us-west-2': 'ami-05f7fcc83babd18eb',
             'eu-west-1': 'ami-0d0fcc08444568042',
             'eu-west-2': 'ami-0567a305f99abe138',
             'eu-west-3': 'ami-0df87cbfbf5e29a6d',
             'eu-central-1': 'ami-042ee7fefd2fbce6c',
             'eu-north-1': 'ami-095afbb53221a2d16',
             'ap-northeast-1': 'ami-04bcb220c319e2d0a',
             'ap-northeast-2': 'ami-0af10927eaebde20b',
             'ap-southeast-1': 'ami-068263e9c9ca3d9dc',
             'ap-southeast-2': 'ami-07ce6711013585e48',
             'ap-south-1': 'ami-0d4304f1bb621ae46',
             'sa-east-1': 'ami-0c297587e3093aa24'
        },
        "non-graphics": {
             "us-east-1": "ami-0d9299304a5e3cfea",
             "ca-central-1": "ami-072dfac76bbba7a11",
             "us-east-2": "ami-08ad93b85eb93fc5c",
             "us-west-1": "ami-084e38470f6754074",
             "us-west-2": "ami-0dab9e46b5aa47961",
             "eu-west-1": "ami-01f10101bddf8ecb8",
             "eu-west-2": "ami-0c57e129d10d47c39",
             "eu-west-3": "ami-0433843d3f015e124",
             "eu-central-1": "ami-01d59b9c6a0031789",
             "eu-north-1": "ami-04994358f2a0bd112",
             "ap-northeast-1": "ami-0cebe66543ec56ce2",
             "ap-northeast-2": "ami-0825e91c25df5a3a1",
             "ap-southeast-1": "ami-08e0bf49e1b2bbd6c",
             "ap-southeast-2": "ami-0058a6d6659ce124f",
             "ap-south-1": "ami-074192a64ff10aa67",
             "sa-east-1": "ami-02938726ac94b1cea",
        }
    }

    SOCA_AUTH_PROVIDER = os.environ.get("SOCA_AUTH_PROVIDER")
    if SOCA_AUTH_PROVIDER == "openldap":
        # LDAP
        LDAP_HOST = soca_config["LdapHost"]
        LDAP_BASE_DN = soca_config["LdapBase"]
        LDAP_ADMIN_PASSWORD_FILE = "/root/OpenLdapAdminPassword.txt"
        LDAP_ADMIN_USERNAME_FILE = "/root/OpenLdapAdminUsername.txt"
        ROOT_DN = 'CN=' + open(LDAP_ADMIN_USERNAME_FILE, 'r').read().rstrip().lstrip() + ',' + LDAP_BASE_DN
        ROOT_PW = open(LDAP_ADMIN_PASSWORD_FILE, 'r').read().rstrip().lstrip()
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
