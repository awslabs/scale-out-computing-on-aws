from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class ApiKeys(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean)
    scope = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime)
    deactivated_on = db.Column(db.DateTime)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class ApplicationProfiles(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    creator = db.Column(db.String(255), nullable=False)
    profile_name = db.Column(db.String(255), nullable=False)
    profile_form = db.Column(db.Text, nullable=False)
    profile_job = db.Column(db.Text, nullable=False)
    profile_interpreter = db.Column(db.Text, nullable=False)
    profile_thumbnail = db.Column(db.Text, nullable=False)
    acl_allowed_users = db.Column(db.Text)
    acl_restricted_users = db.Column(db.Text)
    created_on = db.Column(db.DateTime)
    deactivated_on = db.Column(db.DateTime)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class LinuxDCVSessions(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.String(255), nullable=False)  # Session owner
    tag_uuid = db.Column(db.Text)  # Manage EC2 tag soca:DCVSessionUUID
    session_name = db.Column(db.String(255))  # Session name specified by the user
    session_number = db.Column(db.Integer, nullable=False)  # DCV session number
    session_state = db.Column(db.String(255), nullable=False)  # State of the session (pending/stopped/running)
    session_host_private_dns = db.Column(db.String(255))  # Private DNS of the EC2 host
    session_host_private_ip = db.Column(db.String(255))  # Private IP of the EC2 host
    session_instance_id = db.Column(db.String(255))  # Instance ID of the EC2 host
    session_instance_type = db.Column(db.String(255))  # Instance type of the EC2 host
    session_token = db.Column(db.String(255))  # Unique token associated to each session
    session_id = db.Column(db.String(255), nullable=False)  # DCV session ID, default to console for windows
    session_thumbnail = db.Column(db.Text)  # DCV session screenshot
    session_linux_distribution = db.Column(db.String(255))  # Linux flavor (ALI, centos7, rhel7)
    support_hibernation = db.Column(db.Boolean, nullable=False)  # If EC2 host has hibernation turned on/off
    dcv_authentication_token = db.Column(db.String(255))  # Encrypted authentication token
    is_active = db.Column(db.Boolean)  # If session is active or not
    created_on = db.Column(db.DateTime)  # Timestamp when session was created
    deactivated_on = db.Column(db.DateTime)  # Timestamp when session was deleted
    schedule_monday_start = db.Column(db.Integer)  # What time session will start on Monday, 0 (12AM) to 1440 (12PM) -1 = run all day, -2 = stopped all day
    schedule_monday_stop = db.Column(db.Integer)  # What time session will be stopped on Monday, 0 (12AM) to 1440 (12PM) -1 = run all day, -2 = stopped all day
    schedule_tuesday_start = db.Column(db.Integer)
    schedule_tuesday_stop = db.Column(db.Integer)
    schedule_wednesday_start = db.Column(db.Integer)
    schedule_wednesday_stop = db.Column(db.Integer)
    schedule_thursday_start = db.Column(db.Integer)
    schedule_thursday_stop = db.Column(db.Integer)
    schedule_friday_start = db.Column(db.Integer)
    schedule_friday_stop = db.Column(db.Integer)
    schedule_saturday_start = db.Column(db.Integer)
    schedule_saturday_stop = db.Column(db.Integer)
    schedule_sunday_start = db.Column(db.Integer)
    schedule_sunday_stop = db.Column(db.Integer)
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class WindowsDCVSessions(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.String(255), nullable=False)  # Session owner
    tag_uuid = db.Column(db.Text)  # Manage EC2 tag soca:DCVWindowsSessionUUID
    session_name = db.Column(db.String(255))  # Session name specified by the user
    session_number = db.Column(db.Integer, nullable=False)  # DCV session number
    session_state = db.Column(db.String(255), nullable=False)  # State of the session (pending/stopped/running)
    session_host_private_dns = db.Column(db.String(255))  # Private DNS of the EC2 host
    session_host_private_ip = db.Column(db.String(255))  # Private IP of the EC2 host
    session_instance_id = db.Column(db.String(255))  # Instance ID of the EC2 host
    session_instance_type = db.Column(db.String(255))  # Instance type of the EC2 host
    session_local_admin_password = db.Column(db.String(255), nullable=False)  # Local admin password (if windows)
    session_token = db.Column(db.String(255))  # Unique token associated to each session
    session_id = db.Column(db.String(255), nullable=False)  # DCV session ID, default to console for windows
    session_thumbnail = db.Column(db.Text)  # DCV session screenshot
    support_hibernation = db.Column(db.Boolean, nullable=False)  # If EC2 host has hibernation turned on/off
    dcv_authentication_token = db.Column(db.String(255))  # Encrypted authentication token
    is_active = db.Column(db.Boolean)  # If session is active or not
    created_on = db.Column(db.DateTime)  # Timestamp when session was created
    deactivated_on = db.Column(db.DateTime)  # Timestamp when session was deleted
    schedule_monday_start = db.Column(db.Integer)  # What time session will start on Monday, 0 (12AM) to 1440 (12PM) -1 = run all day, -2 = stopped all day
    schedule_monday_stop = db.Column(db.Integer)  # What time session will be stopped on Monday, 0 (12AM) to 1440 (12PM) -1 = run all day, -2 = stopped all day
    schedule_tuesday_start = db.Column(db.Integer)
    schedule_tuesday_stop = db.Column(db.Integer)
    schedule_wednesday_start = db.Column(db.Integer)
    schedule_wednesday_stop = db.Column(db.Integer)
    schedule_thursday_start = db.Column(db.Integer)
    schedule_thursday_stop = db.Column(db.Integer)
    schedule_friday_start = db.Column(db.Integer)
    schedule_friday_stop = db.Column(db.Integer)
    schedule_saturday_start = db.Column(db.Integer)
    schedule_saturday_stop = db.Column(db.Integer)
    schedule_sunday_start = db.Column(db.Integer)
    schedule_sunday_stop = db.Column(db.Integer)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class AmiList(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ami_id = db.Column(db.String(17), nullable=False)
    ami_type = db.Column(db.String(7), nullable=False)
    ami_label = db.Column(db.Text, nullable=False)
    created_on = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, nullable=False)
    deactivated_on = db.Column(db.DateTime)
    ami_root_disk_size = db.Column(db.Integer)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class ProjectList(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    creator = db.Column(db.String(255), nullable=False)
    project_name = db.Column(db.String(255), nullable=False)
    project_queues = db.Column(db.Text, nullable=False)
    created_on = db.Column(db.DateTime)
    deactivated_on = db.Column(db.DateTime)

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}