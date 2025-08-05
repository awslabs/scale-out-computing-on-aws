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

from flask import Flask, redirect, jsonify, flash, request, session
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
from api.v1.ldap.group import Group
from api.v1.ldap.groups import Groups
from api.v1.ldap.authenticate import Authenticate
from api.v1.login_nodes.list import ListLoginNodes
from api.v1.system.files import Files

from api.v1.user.api_key import ApiKey
from api.v1.user.resources_permissions import GetUserResourcesPermissions

from api.v1.cost_management.pricing import AwsPrice
from api.v1.cost_management.budget import AwsBudgetInfo
from api.v1.cost_management.budgets import AwsBudgets

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

from api.v1.applications.list_applications import Applications

from api.v1.target_nodes.create_target_node import CreateTargetNode
from api.v1.target_nodes.user_data import TargetNodeUserDataManager
from api.v1.target_nodes.software_stacks import TargetNodeSoftwareStacksManager
from api.v1.target_nodes.profiles import TargetNodeProfilesManager
from api.v1.target_nodes.delete_target_node import DeleteTargetNode
from api.v1.target_nodes.list_target_node import ListTargetNode
from api.v1.target_nodes.stop_target_node import StopTargetNode
from api.v1.target_nodes.start_target_node import StartTargetNode
from api.v1.target_nodes.get_target_node_session_state import GetTargetNodeSessionState
from api.v1.target_nodes.update_target_node_schedule import UpdateTargetNodeSchedule
from api.v1.target_nodes.resize_target_node import ResizeTargetNode

from api.v1.containers.ecr.repository import ECRRepository
from api.v1.containers.eks.list_clusters import EKSListClusters
from api.v1.containers.eks.job import EKSJob
from api.v1.containers.eks.jobs import EKSJobs

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

from views.admin.target_nodes.user_data import admin_target_nodes_user_data
from views.admin.target_nodes.software_stacks import admin_target_nodes_software_stacks
from views.admin.target_nodes.profiles import admin_target_nodes_profiles

from views.my_jobs import my_jobs
from views.my_activity import my_activity
from views.dashboard import dashboard
from views.virtual_desktops import virtual_desktops
from views.my_account import my_account
from views.my_files import my_files
from views.submit_job import submit_job
from views.target_nodes import target_nodes
from views.containers import containers


from flask_wtf.csrf import CSRFProtect, CSRFError
from config import app_config

import config

if config.Config.DIRECTORY_AUTH_PROVIDER in [
    "aws_ds_managed_activedirectory",
    "aws_ds_simple_activedirectory",
]:
    from api.v1.ldap.activedirectory.reset_password import Reset
else:
    from api.v1.ldap.reset_password import Reset
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

import soca_samples
import os
import stat
from utils.logger import SocaLogger
import json

from extensions import db, scheduler
import feature_flags

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


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash(
        "Token has expired. As a security measure we have refreshed your token. Please re-submit your request again.",
        "warning",
    )
    return redirect(request.referrer or "/")


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

@app.errorhandler(404)
def page_not_found(_e):
    return redirect("/")


@app.context_processor
def inject_globals():
    # Variables available on all templates
    return {
        "feature_flags": feature_flags.FEATURE_FLAGS,
        "admin": session.get("sudoers", False),
        "user": session.get("user", ""),
    }


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
    api.add_resource(GetUserResourcesPermissions, "/api/user/resources_permissions")
    # System
    api.add_resource(Files, "/api/system/files")

    # Cost Management
    api.add_resource(AwsPrice, "/api/cost_management/pricing")
    api.add_resource(AwsBudgetInfo, "/api/cost_management/budget")
    api.add_resource(AwsBudgets, "/api/cost_management/budgets")

    # Containers
    api.add_resource(ECRRepository, "/api/containers/ecr/repository")
    api.add_resource(EKSListClusters, "/api/containers/eks/list_clusters")
    api.add_resource(EKSJob, "/api/containers/eks/job")
    api.add_resource(EKSJobs, "/api/containers/eks/jobs")

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

    # Applications
    api.add_resource(Applications, "/api/applications/list_applications")

    # Target Nodes
    api.add_resource(CreateTargetNode, "/api/target_nodes/create")
    api.add_resource(DeleteTargetNode, "/api/target_nodes/delete")
    api.add_resource(StopTargetNode, "/api/target_nodes/stop")
    api.add_resource(StartTargetNode, "/api/target_nodes/start")
    api.add_resource(TargetNodeUserDataManager, "/api/target_nodes/user_data")
    api.add_resource(
        TargetNodeSoftwareStacksManager, "/api/target_nodes/software_stacks"
    )
    api.add_resource(TargetNodeProfilesManager, "/api/target_nodes/profiles")
    api.add_resource(ListTargetNode, "/api/target_nodes/list")
    api.add_resource(GetTargetNodeSessionState, "/api/target_nodes/session_state")
    api.add_resource(UpdateTargetNodeSchedule, "/api/target_nodes/schedule")
    api.add_resource(ResizeTargetNode, "/api/target_nodes/resize")

    # Project
    api.add_resource(ProjectsManager, "/api/projects")

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
    app.register_blueprint(target_nodes)
    app.register_blueprint(admin_target_nodes_user_data)
    app.register_blueprint(admin_target_nodes_software_stacks)
    app.register_blueprint(admin_target_nodes_profiles)
    app.register_blueprint(containers)

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
        "scheduled_tasks_target_nodes_session_state_watcher",
        "logs/scheduled_tasks/target_nodes/session_state_watcher.log",
    )
    setup_logger(
        "scheduled_tasks_target_nodes_schedule_management",
        "logs/scheduled_tasks/target_nodes/scheduled_tasks_target_nodes_schedule_management.log",
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
    from scheduled_tasks.target_nodes.session_state_watcher import (
        target_nodes_session_state_watcher,
    )
    from scheduled_tasks.target_nodes.schedule_management import (
        target_nodes_schedule_management,
    )
    from scheduled_tasks.clean_tmp_folders import clean_tmp_folders
    from scheduled_tasks.create_db_backup import backup_db

    # Create default content
    soca_samples.insert_default_vdi_profile()
    soca_samples.insert_default_software_stacks()
    soca_samples.insert_default_test_web_based_job_submission_application()
    soca_samples.insert_default_target_host_user_data()
    soca_samples.insert_default_target_node_profile()
    soca_samples.insert_default_projects()

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
        args=[app],
        trigger=IntervalTrigger(minutes=30),
        id="auto_terminate_stopped_instance",
        replace_existing=True,
    )

    # Task: Virtual desktops schedule management
    scheduler.add_job(
        virtual_desktops_schedule_management,
        args=[app],
        trigger=CronTrigger(
            minute="0,16,32,47"
        ),  # every hour , every 16 minutes (as users can adjust schedule every 15 mins)
        id="virtual_desktops_schedule_management",
        replace_existing=True,
    )

    # Task: Virtual desktops session state watcher every 1 minute
    scheduler.add_job(
        virtual_desktops_session_state_watcher,
        args=[app],
        trigger=IntervalTrigger(minutes=1),
        id="virtual_desktops_session_state_watcher",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Virtual desktops session error watcher every 5 minutes
    scheduler.add_job(
        virtual_desktops_session_error_watcher,
        args=[app],
        trigger=IntervalTrigger(minutes=5),
        id="virtual_desktops_session_error_watcher",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Target Node session state watcher every 1 minute
    scheduler.add_job(
        target_nodes_session_state_watcher,
        args=[app],
        trigger=IntervalTrigger(minutes=1),
        id="target_nodes_session_state_watcher",
        replace_existing=True,
        max_instances=1,
    )

    # Task: Target Node schedule management
    scheduler.add_job(
        target_nodes_schedule_management,
        args=[app],
        trigger=CronTrigger(
            minute="0,16,32,47"
        ),  # every hour , every 16 minutes (as users can adjust schedule every 15 mins)
        id="target_nodes_schedule_management",
        replace_existing=True,
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
