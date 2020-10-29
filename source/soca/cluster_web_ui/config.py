import os
from datetime import timedelta
import secrets
from cryptography.fernet import Fernet

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    # APP
    DEBUG = False
    TESTING = False
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
                        '/media', '/opt', '/proc', '/root', '/run', '/sbin', '/srv', '/sys', '/tmp', '/usr',
                        '/var']  # List of folders not accessible via the web ui
    DEFAULT_CACHE_TIME = 120  # 2 minutes. Change this value to optimize performance in case you have a large number of concurrent user
    MAX_UPLOAD_FILE = 5120  # 5 GB
    MAX_UPLOAD_TIMEOUT = 1800000  # 30 minutes
    ALLOW_DOWNLOAD_FROM_PORTAL = True  # Give user ability to download files from the web portal
    MAX_SIZE_ONLINE_PREVIEW = 150000000  # in bytes (150mb by default), maximum size of file that can be visualized via the web editor
    MAX_ARCHIVE_SIZE = 150000000  # in bytes (150mb by default), maximum size of archive generated when downloading multiple files at once
    DAILY_BACKUP_COUNT = 15  # Keep 15 latest daily backups
    KIBANA_JOB_INDEX = "job*"  # Default index to look for /my_activity. Change it something more specific if using more than 1 index with name ~ "job*"

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
    COGNITO_CALLBACK_URL= "<YOUR_CALLBACK_URL>"

    # DCV General
    DCV_AUTH_DIR = "/var/run/dcvsimpleextauth"
    DCV_SIMPLE_AUTH = "/usr/libexec/dcvsimpleextauth.py"
    DCV_SESSION_LOCATION = "tmp/dcv_sessions"
    DCV_FORCE_INSTANCE_HIBERNATE_SUPPORT = False  # If True, users can only provision instances that support hibernation
    DCV_TOKEN_SYMMETRIC_KEY = os.environ["SOCA_DCV_TOKEN_SYMMETRIC_KEY"]  # used to encrypt/decrypt and validate DCV session auth
    DCV_BLACKLIST_INSTANCE_TYPE = ['metal', 'nano', 'micro', 'p3', 'p2', 'p3dn', 'g2']  # This instance type won't be visible on the dropdown menu
    DCV_IDLE_CPU_THRESHOLD = 15  # SOCA will NOT hibernate/stop an instance if current CPU usage % is over this value

    # DCV Linux
    DCV_LINUX_SESSION_COUNT = 4
    DCV_LINUX_ALLOW_INSTANCE_CHANGE = True  # Allow user to change their instance type if their DCV session is stopped
    DCV_LINUX_HIBERNATE_IDLE_SESSION = 1  # In hours. Windows DCV sessions will be hibernated to save cost if there is no active connection within the time specified. 0 to disable
    DCV_LINUX_STOP_IDLE_SESSION = 1  # In hours. Windows DCV sessions will be stopped to save cost if there is no active connection within the time specified. 0 to disable
    DCV_LINUX_TERMINATE_STOPPED_SESSION = 0  # In hours. Stopped Windows DCV will be permanently terminated if user won't restart it within the time specified. 0 to disable
    DCV_LINUX_DEFAULT_SCHEDULE_START = 480  # 8 AM
    DCV_LINUX_DEFAULT_SCHEDULE_STOP = 1140  # 7PM

    # DCV Windows
    DCV_WINDOWS_SESSION_COUNT = 4
    DCV_WINDOWS_ALLOW_INSTANCE_CHANGE = True  # Allow user to change their instance type if their DCV session is stopped
    DCV_WINDOWS_HIBERNATE_IDLE_SESSION = 1  # In hours. Windows DCV sessions will be hibernated to save cost if there is no active connection within the time specified. 0 to disable
    DCV_WINDOWS_STOP_IDLE_SESSION = 1  # In hours. Windows DCV sessions will be stopped to save cost if there is no active connection within the time specified. 0 to disable
    DCV_WINDOWS_TERMINATE_STOPPED_SESSION = 0  # In hours. Stopped Windows DCV will be permanently terminated if user won't restart it within the time specified. 0 to disable
    DCV_WINDOWS_AUTOLOGON = True  # enable or disable autologon. If disabled user will have to manually input Windows password
    DCV_WINDOWS_DEFAULT_SCHEDULE_START = 480  # 8 AM
    DCV_WINDOWS_DEFAULT_SCHEDULE_STOP = 1140  # 7PM
    DCV_WINDOWS_AMI = {"graphics": {"us-east-1": "ami-035a352d4d53371dc",
                                    "us-east-2": "ami-0e513ab3dde457471",
                                    "us-west-1": "ami-0a7cc05863d8c367c",
                                    "us-west-2": "ami-08ec961045e722c40",
                                    "eu-central-1": "ami-0da51c48c5e5f8e0e",
                                    "eu-west-1": "ami-0edc64da5375c6c34",
                                    "eu-west-2": "ami-027221529e78599f9",
                                    "eu-west-3": "ami-03453f73099c2010b",
                                    "ap-southeast-1": "ami-0e14ff207c0bd2e5d",
                                    "ap-southeast-2": "ami-0717865967421051e",
                                    "ap-northeast-2": "ami-05876cd44f021253d",
                                    "ap-northeast-1": "ami-0a9fb743d72e209ca",
                                    "ap-south-1": "ami-09c1d03de366041a4"},
                       "non-graphics": {"us-east-1": "ami-021660b17250fbc9b",
                                        "us-east-2": "ami-03d379fd8144e0be7",
                                        "us-west-1": "ami-0b1004c6b09ece7e7",
                                        "us-west-2": "ami-0e7e8e1d3f5f5d731",
                                        "eu-central-1": "ami-0cc92c26fe29f163a",
                                        "eu-west-1": "ami-039ab4fa2e97f7bf2",
                                        "eu-west-2": "ami-0d29c4ac068195b68",
                                        "eu-west-3": "ami-079ec05d5cb6e88cf",
                                        "ap-southeast-1": "ami-039280ee1e354d8dd",
                                        "ap-southeast-2": "ami-0eb1dd92d2dd137e9",
                                        "ap-northeast-2": "ami-09a9fe0bfb14bebb5",
                                        "ap-northeast-1": "ami-0101345c4c334941c",
                                        "ap-south-1": "ami-08e852f6df553818a"}}
    # LDAP
    LDAP_HOST = "127.0.0.1"
    LDAP_BASE_DN = "dc=soca,dc=local"
    LDAP_ADMIN_PASSWORD_FILE = "/root/OpenLdapAdminPassword.txt"
    LDAP_ADMIN_USERNAME_FILE = "/root/OpenLdapAdminUsername.txt"
    ROOT_DN = 'CN=' + open(LDAP_ADMIN_USERNAME_FILE, 'r').read().rstrip().lstrip() + ',' + LDAP_BASE_DN
    ROOT_PW = open(LDAP_ADMIN_PASSWORD_FILE, 'r').read().rstrip().lstrip()

    # PBS
    PBS_QSTAT = "/opt/pbs/bin/qstat"
    PBS_QDEL = "/opt/pbs/bin/qdel"
    PBS_QSUB = "/opt/pbs/bin/qsub"
    PBS_QMGR = "/opt/pbs/bin/qmgr"

    # SSH
    SSH_PRIVATE_KEY_LOCATION = "tmp/ssh"


app_config = Config()
