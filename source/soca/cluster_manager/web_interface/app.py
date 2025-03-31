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

import logging.config

from flask import Flask, redirect, jsonify
from flask_restful import Api
from flask_session import Session
from werkzeug.debug import DebuggedApplication
import validators

from api.v1.scheduler.pbspro.job import Job
from api.v1.scheduler.pbspro.jobs import Jobs
from api.v1.scheduler.pbspro.queue import Queue
from api.v1.scheduler.pbspro.queues import Queues

from api.v1.ldap.sudo import Sudo
from api.v1.ldap.ids import Ids
from api.v1.ldap.user import User
from api.v1.ldap.users import Users
from api.v1.user.api_key import ApiKey
from api.v1.ldap.group import Group
from api.v1.ldap.groups import Groups
from api.v1.ldap.authenticate import Authenticate
from api.v1.login_nodes.list import ListLoginNodes
from api.v1.system.files import Files
from api.v1.system.aws_price import AwsPrice

from api.v1.dcv.authenticator import DcvAuthenticator
from api.v1.dcv.create_virtual_desktop import CreateVirtualDesktop
from api.v1.dcv.list_virtual_desktops import ListVirtualDesktops
from api.v1.dcv.list_all_virtual_desktops import ListAllVirtualDesktops
from api.v1.dcv.delete_virtual_desktop import DeleteVirtualDesktop
from api.v1.dcv.stop_virtual_desktop import StopVirtualDesktop
from api.v1.dcv.start_virtual_desktop import StartVirtualDesktop
from api.v1.dcv.resize_virtual_desktop import ResizeVirtualDesktop
from api.v1.dcv.update_virtual_desktop_schedule import UpdateVirtualDesktopSchedule
from api.v1.dcv.get_virtual_desktops_session_state import GetVirtualDesktopsSessionState
from api.v1.dcv.software_stacks import SoftwareStacksManager
from api.v1.dcv.profiles import VirtualDesktopProfilesManager

from api.v1.projects.projects import ProjectsManager
from api.v1.projects.get_projects_for_user import ProjectsByUser

from views.index import index
from views.ssh import ssh
from views.sftp import sftp
from views.my_api_key import my_api_key
from views.admin.users import admin_users
from views.admin.queues import admin_queues
from views.admin.groups import admin_groups
from views.admin.applications import admin_applications
from views.admin.virtual_desktops.software_stacks import (
    admin_virtual_desktops_software_stacks,
)
from views.admin.virtual_desktops.profiles import admin_virtual_desktops_profiles
from views.admin.virtual_desktops.list_all_virtual_desktops import (
    admin_virtual_desktops_list_all,
)
from views.admin.projects.projects import admin_projects
from views.my_jobs import my_jobs
from views.my_activity import my_activity
from views.dashboard import dashboard
from views.virtual_desktops import virtual_desktops
from views.my_account import my_account
from views.my_files import my_files
from views.submit_job import submit_job
from flask_wtf.csrf import CSRFProtect
from config import app_config
from flask_swagger import swagger
from swagger_ui import api_doc
import config

if config.Config.DIRECTORY_AUTH_PROVIDER in [
    "aws_ds_managed_activedirectory",
    "aws_ds_simple_activedirectory",
]:
    from api.v1.ldap.activedirectory.reset_password import Reset
else:
    from api.v1.ldap.reset_password import Reset
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

from models import db
import soca_samples
import os
import stat
from utils.logger import SocaLogger
import json

app = Flask(__name__)


# Custom Jinja2 filters
@app.template_filter("folder_name_truncate")
def folder_name_truncate(folder_name):
    # This make sure folders with long name on /my_files are displayed correctly
    if folder_name.__len__() < 20:
        return folder_name
    else:
        split_number = [20, 40, 60]
        for number in split_number:
            try:
                if (
                    folder_name[number] != "-"
                    and folder_name[number - 1] != "-"
                    and folder_name[number + 1] != "-"
                ):
                    folder_name = folder_name[:number] + "-" + folder_name[number:]
            except IndexError:
                break
        return folder_name


@app.context_processor
def inject_global_template_variables():
    _global_variables = {}
    _amazon_q_business_url = config.Config.AMAZON_Q_BUSINESS_URL
    if validators.url(_amazon_q_business_url) is True:
        _global_variables["AMAZON_Q_BUSINESS_URL"] = _amazon_q_business_url
    else:
        print("AMAZON_Q_BUSINESS_URL is not a valid URL, default value to False")
        _global_variables["AMAZON_Q_BUSINESS_URL"] = False

    return _global_variables


@app.template_filter("from_json")
def from_json(value):
    """Custom filter to parse JSON string into a Python dict."""
    return json.loads(value)


app.jinja_env.filters["from_json"] = from_json
app.jinja_env.filters["folder_name_truncate"] = folder_name_truncate
app.jinja_env.add_extension("jinja2.ext.do")


@app.route("/api/doc/swagger.json")
def spec():
    swag = swagger(app)
    swag["info"]["version"] = "1.0"
    swag["info"]["title"] = "SOCA Web API"
    swag["info"]["description"] = (
        "<h3>Documentation for your Scale-Out Computing on AWS (SOCA) API</h3><hr>"
        "<li>User and Admin Documentation: https://awslabs.github.io/scale-out-computing-on-aws-documentation/</li>"
        "<li>CodeBase: https://github.com/awslabs/scale-out-computing-on-aws</li>"
    )
    return jsonify(swag)


@app.errorhandler(404)
def page_not_found(_e):
    return redirect("/")


def setup_logger(name: str, file_path: str):
    _log_folder = os.path.dirname(file_path)
    os.makedirs(_log_folder, exist_ok=True)
    for dirpath, dirnames, filenames in os.walk(_log_folder):
        os.chmod(dirpath, 0o750)

    logger = SocaLogger(name=name).timed_rotating_file_handler(
        file_path=file_path,
        backup_count=config.Config.LOG_DAILY_BACKUP_COUNT,
    )
    app.logger.addHandler(logging.getLogger(name))


with app.app_context():
    csrf = CSRFProtect(app)
    csrf.exempt("api")

    # Register configuration
    app.config.from_object(app_config)

    if app_config.DEBUG is True:
        app.debug = True
        app.wsgi_app = DebuggedApplication(app.wsgi_app, True)

    # Add API
    api = Api(app, decorators=[csrf.exempt])

    # Auth provider can be either openldap, aws_ds_simple_activedirectory, or activedirectory
    api.add_resource(Sudo, "/api/ldap/sudo")
    api.add_resource(Authenticate, "/api/ldap/authenticate")
    api.add_resource(Ids, "/api/ldap/ids")
    api.add_resource(User, "/api/ldap/user")
    api.add_resource(Users, "/api/ldap/users")
    api.add_resource(Group, "/api/ldap/group")
    api.add_resource(Groups, "/api/ldap/groups")
    # Users
    api.add_resource(ApiKey, "/api/user/api_key")
    api.add_resource(Reset, "/api/user/reset_password")
    # System
    api.add_resource(Files, "/api/system/files")
    api.add_resource(AwsPrice, "/api/system/aws_price")
    # DCV
    api.add_resource(DcvAuthenticator, "/api/dcv/authenticator")
    api.add_resource(ListVirtualDesktops, "/api/dcv/virtual_desktops/list")
    api.add_resource(ListAllVirtualDesktops, "/api/dcv/virtual_desktops/list_all")
    api.add_resource(CreateVirtualDesktop, "/api/dcv/virtual_desktops/create")
    api.add_resource(DeleteVirtualDesktop, "/api/dcv/virtual_desktops/delete")
    api.add_resource(StopVirtualDesktop, "/api/dcv/virtual_desktops/stop")
    api.add_resource(StartVirtualDesktop, "/api/dcv/virtual_desktops/start")
    api.add_resource(ResizeVirtualDesktop, "/api/dcv/virtual_desktops/resize")
    api.add_resource(UpdateVirtualDesktopSchedule, "/api/dcv/virtual_desktops/schedule")
    api.add_resource(
        GetVirtualDesktopsSessionState, "/api/dcv/virtual_desktops/session_state"
    )
    api.add_resource(SoftwareStacksManager, "/api/dcv/virtual_desktops/software_stacks")
    api.add_resource(
        VirtualDesktopProfilesManager, "/api/dcv/virtual_desktops/profiles"
    )

    # Project
    api.add_resource(ProjectsManager, "/api/projects")
    api.add_resource(ProjectsByUser, "/api/projects/by_user")

    # Scheduler
    api.add_resource(Job, "/api/scheduler/job")
    api.add_resource(Jobs, "/api/scheduler/jobs")
    api.add_resource(Queue, "/api/scheduler/queue")
    api.add_resource(Queues, "/api/scheduler/queues")

    # Login Nodes
    api.add_resource(ListLoginNodes, "/api/login_nodes/list")

    # Register views
    app.register_blueprint(index)
    app.register_blueprint(my_api_key)
    app.register_blueprint(my_account)
    app.register_blueprint(admin_users)
    app.register_blueprint(admin_queues)
    app.register_blueprint(admin_groups)
    app.register_blueprint(admin_applications)
    app.register_blueprint(admin_virtual_desktops_software_stacks)
    app.register_blueprint(admin_virtual_desktops_profiles)
    app.register_blueprint(admin_virtual_desktops_list_all)
    app.register_blueprint(admin_projects)
    app.register_blueprint(my_files)
    app.register_blueprint(submit_job)
    app.register_blueprint(ssh)
    app.register_blueprint(sftp)
    app.register_blueprint(my_jobs)
    app.register_blueprint(virtual_desktops)
    app.register_blueprint(dashboard)
    app.register_blueprint(my_activity)
    # Logger
    setup_logger("soca_logger", "logs/web_interface.log")
    setup_logger(
        "scheduled_tasks_virtual_desktops_schedule_management",
        "logs/scheduled_tasks/virtual_desktops/schedule_management.log",
    )
    setup_logger(
        "scheduled_tasks_virtual_desktops_session_state_watcher",
        "logs/scheduled_tasks/virtual_desktops/session_state_watcher.log",
    )
    setup_logger(
        "scheduled_tasks_virtual_desktops_session_error_watcher",
        "logs/scheduled_tasks/virtual_desktops/session_error_watcher.log",
    )
    setup_logger(
        "scheduled_tasks_db_backup",
        "logs/scheduled_tasks/db_backup.log",
    )

    db.app = app
    db.init_app(app)
    db.create_all()
    basedir = os.path.abspath(os.path.dirname(__file__))
    os.chmod(os.path.join(basedir, "db.sqlite"), stat.S_IWUSR + stat.S_IRUSR)
    app_session = Session(app)

    # This only takes place in SQL mode
    if config.Config.SESSION_TYPE == "sqlalchemy":
        app_session.app.session_interface.db.create_all()

    # now import scheduled tasks
    from scheduled_tasks.virtual_desktops.session_state_watcher import (
        virtual_desktops_session_state_watcher,
    )
    from scheduled_tasks.virtual_desktops.session_error_watcher import (
        virtual_desktops_session_error_watcher,
    )

    from scheduled_tasks.virtual_desktops.schedule_management import (
        virtual_desktops_schedule_management,
        auto_terminate_stopped_instance,
    )
    from scheduled_tasks.clean_tmp_folders import clean_tmp_folders
    from scheduled_tasks.create_db_backup import backup_db

    # Create default content
    soca_samples.insert_default_vdi_profile()
    soca_samples.insert_default_software_stacks()
    soca_samples.insert_default_projects()
    soca_samples.insert_default_test_web_based_job_submission_application()

    api_doc(
        app,
        config_url=config.Config.FLASK_ENDPOINT + "/api/doc/swagger.json",
        url_prefix="/api/doc",
        title="SOCA API Documentation",
    )

    # Schedule tasks using the scheduler
    scheduler = BackgroundScheduler()

    # Task: Backup DB every 12 hours
    scheduler.add_job(
        backup_db,
        trigger=IntervalTrigger(hours=12),
        id="scheduled_tasks_db_backup",
        replace_existing=True,
    )

    # Task: Auto terminate stopped instances every 30 minutes
    scheduler.add_job(
        auto_terminate_stopped_instance,
        trigger=IntervalTrigger(minutes=30),
        id="auto_terminate_stopped_instance",
        replace_existing=True,
    )

    # Task: Virtual desktops schedule management
    scheduler.add_job(
        virtual_desktops_schedule_management,
        trigger=CronTrigger(
            minute="0,16,32,47"
        ),  # every hour , every 16 minutes (as users can adjust schedule every 15 mins)
        id="virtual_desktops_schedule_management",
        replace_existing=True,
    )

    # Task: Virtual desktops session state watcher every 1 minute
    scheduler.add_job(
        virtual_desktops_session_state_watcher,
        trigger=IntervalTrigger(minutes=1),
        id="virtual_desktops_session_state_watcher",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Virtual desktops session error watcher every 5 minutes
    scheduler.add_job(
        virtual_desktops_session_error_watcher,
        trigger=IntervalTrigger(minutes=5),
        id="virtual_desktops_session_error_watcher",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Clean temp folders every 1 hour
    scheduler.add_job(
        clean_tmp_folders,
        trigger=IntervalTrigger(hours=1),
        id="clean_tmp_folders",
        replace_existing=True,
    )

    scheduler.start()

if __name__ == "__main__":
    app.run()
