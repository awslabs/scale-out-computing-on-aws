import logging.config
from flask import Flask, redirect, jsonify
from flask_restful import Api
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from api.v1.scheduler.pbspro.job import Job
from api.v1.scheduler.pbspro.jobs import Jobs
from api.v1.scheduler.pbspro.queue import Queue
from api.v1.scheduler.pbspro.queues import Queues
from api.v1.ldap.sudo import Sudo
from api.v1.ldap.ids import Ids
from api.v1.ldap.user import User
from api.v1.ldap.users import Users
from api.v1.user.reset_password import Reset
from api.v1.user.api_key import ApiKey
from api.v1.ldap.group import Group
from api.v1.ldap.groups import Groups
from api.v1.ldap.authenticate import Authenticate
from api.v1.system.files import Files
from api.v1.system.aws_price import AwsPrice
from api.v1.dcv.authenticator import DcvAuthenticator
from views.index import index
from views.ssh import ssh
from views.sftp import sftp
from views.my_api_key import my_api_key
from views.admin.users import admin_users
from views.admin.queues import admin_queues
from views.admin.groups import admin_groups
from views.admin.applications import admin_applications
from views.admin.ami_management import admin_ami_management
from views.my_jobs import my_jobs
from views.my_activity import my_activity
from views.dashboard import dashboard
from views.remote_desktop import remote_desktop
from views.remote_desktop_windows import remote_desktop_windows
from views.my_account import my_account
from views.my_files import my_files
from views.submit_job import submit_job
from scheduled_tasks.clean_tmp_folders import clean_tmp_folders
from scheduled_tasks.manage_dcv_instances_lifecycle import auto_terminate_stopped_instance, schedule_auto_start, schedule_auto_stop
from flask_wtf.csrf import CSRFProtect
from config import app_config
from flask_swagger import swagger
from swagger_ui import api_doc
import config
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from flask_apscheduler import APScheduler
#from apscheduler.schedulers.background import BackgroundScheduler
from models import db

app = Flask(__name__)

# Custom Jinja2 filters

@app.template_filter('folder_name_truncate')
def folder_name_truncate(folder_name):
    # This make sure folders with long name on /my_files are displayed correctly
    if folder_name.__len__() < 20:
        return folder_name
    else:
        split_number = [20, 40, 60]
        for number in split_number:
            try:
                if folder_name[number] != "-" and folder_name[number-1] != "-" and folder_name[number+1] != "-":
                    folder_name = folder_name[:number] + '-' + folder_name[number:]
            except IndexError:
                break
        return folder_name
app.jinja_env.filters['folder_name_truncate'] = folder_name_truncate

@app.route("/api/doc/swagger.json")
def spec():
    swag = swagger(app)
    swag['info']['version'] = "1.0"
    swag['info']['title'] = "SOCA Web API"
    swag['info']['description'] = "<h3>Documentation for your Scale-Out Computing on AWS (SOCA) API</h3><hr>" \
                                  "<li>User and Admin Documentation: https://awslabs.github.io/scale-out-computing-on-aws/</li>" \
                                  "<li>CodeBase: https://github.com/awslabs/scale-out-computing-on-aws</li>"
    return jsonify(swag)


@app.errorhandler(404)
def page_not_found(e):
    return redirect('/')

# Manage logger
dict_config = {
    'version': 1,
    'formatters': {
        'default': {
            'format': '[%(asctime)s] [%(levelname)s] [%(module)s] [%(message)s]',
        }
    },
    'handlers': {
        'default': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': "logs/application.log",
            'when': "midnight",
            'interval': 1,
            'backupCount': config.Config.DAILY_BACKUP_COUNT
        },
        'api': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': "logs/api.log",
            'when': "midnight",
            'interval': 1,
            'backupCount': config.Config.DAILY_BACKUP_COUNT
        },
        'scheduled_tasks': {
            'level': 'DEBUG',
            'formatter': 'default',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': "logs/scheduled_tasks.log",
            'when': "midnight",
            'interval': 1,
            'backupCount': config.Config.DAILY_BACKUP_COUNT
        },
    },
    'loggers': {
        'application': {
            'handlers': ["default"],
            'level': 'DEBUG',
        },
        'api': {
            'handlers': ["api"],
            'level': 'DEBUG',
        },
        'scheduled_tasks': {
            'handlers': ["scheduled_tasks"],
            'level': 'DEBUG',
        }
    }
}


class Config(object):
    JOBS = [
        {
            'id': 'auto_terminate_stopped_instance',
            'func': auto_terminate_stopped_instance,
            'trigger': 'interval',
            'minutes': 30
        },
        {
            'id': 'schedule_auto_start',
            'func': schedule_auto_start,
            'trigger': 'interval',
            'minutes': 10
        },
        {
            'id': 'schedule_auto_stop',
            'func': schedule_auto_stop,
            'trigger': 'interval',
            'minutes': 5
        },
        {
            'id': 'clean_tmp_folders',
            'func': clean_tmp_folders,
            'trigger': 'interval',
            'hours': 1
        }
    ]

    SCHEDULER_API_ENABLED = True
    SESSION_SQLALCHEMY = SQLAlchemy(app)


with app.app_context():
    csrf = CSRFProtect(app)
    csrf.exempt("api")

    # Register routes
    app.config.from_object(app_config)

    # Add API
    api = Api(app, decorators=[csrf.exempt])

    # LDAP
    api.add_resource(Sudo, '/api/ldap/sudo')
    api.add_resource(Authenticate, '/api/ldap/authenticate')
    api.add_resource(Ids, '/api/ldap/ids')
    api.add_resource(User, '/api/ldap/user')
    api.add_resource(Users, '/api/ldap/users')
    api.add_resource(Group, '/api/ldap/group')
    api.add_resource(Groups, '/api/ldap/groups')
    # Users
    api.add_resource(ApiKey, '/api/user/api_key')
    api.add_resource(Reset, '/api/user/reset_password')
    # System
    api.add_resource(Files, '/api/system/files')
    api.add_resource(AwsPrice, '/api/system/aws_price')
    api.add_resource(DcvAuthenticator, '/api/dcv/authenticator')
    # Scheduler
    api.add_resource(Job, '/api/scheduler/job')
    api.add_resource(Jobs, '/api/scheduler/jobs')
    api.add_resource(Queue, '/api/scheduler/queue')
    api.add_resource(Queues, '/api/scheduler/queues')

    # Register views
    app.register_blueprint(index)
    app.register_blueprint(my_api_key)
    app.register_blueprint(my_account)
    app.register_blueprint(admin_users)
    app.register_blueprint(admin_queues)
    app.register_blueprint(admin_groups)
    app.register_blueprint(admin_applications)
    app.register_blueprint(admin_ami_management)
    app.register_blueprint(my_files)
    app.register_blueprint(submit_job)
    app.register_blueprint(ssh)
    app.register_blueprint(sftp)
    app.register_blueprint(my_jobs)
    app.register_blueprint(remote_desktop)
    app.register_blueprint(remote_desktop_windows)
    app.register_blueprint(dashboard)
    app.register_blueprint(my_activity)
    logging.config.dictConfig(dict_config)
    app.logger.addHandler(logging.getLogger("application"))
    app.logger.addHandler(logging.getLogger("api"))
    app.logger.addHandler(logging.getLogger("scheduled_tasks"))
    db.app = app
    db.init_app(app)
    db.create_all()
    app_session = Session(app)
    app_session.app.session_interface.db.create_all()
    app.config.from_object(Config())
    api_doc(app, config_url=config.Config.FLASK_ENDPOINT + "/api/doc/swagger.json", url_prefix="/api/doc", title="SOCA API Documentation")
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()

if __name__ == '__main__':
    app.run()


