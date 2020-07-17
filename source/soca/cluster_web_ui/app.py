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
from views.index import index
from views.ssh import ssh
from views.sftp import sftp
from views.my_api_key import my_api_key
from views.admin.users import admin_users
from views.admin.queues import admin_queues
from views.admin.groups import admin_groups
from views.admin.applications import admin_applications
from views.my_jobs import my_jobs
from views.my_activity import my_activity
from views.dashboard import dashboard
from views.remote_desktop import remote_desktop
from views.my_account import my_account
from views.my_files import my_files
from views.submit_job import submit_job
from flask_wtf.csrf import CSRFProtect
from config import app_config
from models import db
from flask_swagger import swagger
from swagger_ui import api_doc
import config
from apscheduler.schedulers.background import BackgroundScheduler
import glob
import os

app = Flask(__name__)
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
app.register_blueprint(my_files)
app.register_blueprint(submit_job)
app.register_blueprint(ssh)
app.register_blueprint(sftp)
app.register_blueprint(my_jobs)
app.register_blueprint(remote_desktop)
app.register_blueprint(dashboard)
app.register_blueprint(my_activity)



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

@app.route("/api/swagger.json")
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
            'filename': "soca_api.log",
            'when': "midnight",
            'interval': 1,
            'backupCount': config.Config.DAILY_BACKUP_COUNT
        },
    },
    'loggers': {
        'api_log': {
            'handlers': ["default"],
            'level': 'DEBUG',
        },
    }
}

logger = logging.getLogger("api_log")
logging.config.dictConfig(dict_config)
app.logger.addHandler(logger)

# Scheduled tasks
def clean_tmp_folders():
    directories = ["tmp/zip_downloads/*", "tmp/ssh/*"]
    for directory in directories:
        logger.info("Remove files inside " + directory)
        files = glob.glob(directory)
        for f in files:
            os.remove(f)


sched = BackgroundScheduler(daemon=False)
sched.add_job(clean_tmp_folders, 'interval', hours=1)
sched.start()

with app.app_context():
    db.init_app(app)
    db.create_all()
    app_session = Session(app)
    app_session.app.session_interface.db.create_all()
    app.config["SESSION_SQLALCHEMY"] = SQLAlchemy(app)
    api_doc(app, config_url=config.Config.FLASK_ENDPOINT + "/api/swagger.json", url_prefix="/api/doc", title="SOCA API Documentation",)

if __name__ == '__main__':
    app.run()


