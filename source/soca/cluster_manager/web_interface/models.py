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

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship
from extensions import db

# Association table to link projects and software stacks
project_software_stack_association = Table(
    "project_software_stack",
    db.Model.metadata,
    db.Column(
        "project_id",
        db.Integer,
        ForeignKey("projects.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "software_stack_id",
        db.Integer,
        ForeignKey("software_stacks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class ApiKeys(db.Model):
    __tablename__ = "api_keys"
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
    __tablename__ = "application_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_by = db.Column(db.String(255), nullable=False)
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


class VirtualDesktopSessions(db.Model):
    __tablename__ = "virtual_desktop_sessions"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    is_active = db.Column(db.Boolean, nullable=False)  # If session is active or not
    created_on = db.Column(
        db.DateTime, nullable=False
    )  # Timestamp when session was created
    deactivated_on = db.Column(db.DateTime)  # Timestamp when session was deleted
    deactivated_by = db.Column(db.String(255))
    stack_name = db.Column(db.String(255))  # Name of the CloudFormation Stack
    session_uuid = db.Column(
        db.Text, nullable=False
    )  # Manage EC2 tag soca:DCVSessionUUID as well as session ID
    session_name = db.Column(
        db.String(255), nullable=False
    )  # Session name specified by the user
    session_state = db.Column(
        db.String(255), nullable=False
    )  # State of the session (pending/stopped/running)
    session_type = db.Column(db.String(255), nullable=False)  # console or virtual
    session_state_latest_change_time = db.Column(db.DateTime, nullable=False)
    session_local_admin_password = db.Column(
        db.String(255)
    )  # Local admin password for the session (Optional)
    session_token = db.Column(db.String(255))  # Unique token associated to each session
    schedule = db.Column(db.Text, nullable=False)  # DCV session schedule
    session_thumbnail = db.Column(db.Text)  # DCV session screenshot
    software_stack_id = Column(
        Integer, ForeignKey("software_stacks.id"), nullable=False
    )  # ID of the software Stack deployed on this machine

    # DCV Specific
    session_owner = db.Column(db.String(255), nullable=False)  # Session owner
    session_id = db.Column(
        db.Text, nullable=False
    )  # Same as session_uuid for Linux, default to console for windows. This is the ID of your DCV Session
    authentication_token = db.Column(
        db.String(255)
    )  # Encrypted authentication token, contains session_token and others info

    # Instance Specific
    instance_private_dns = db.Column(db.String(255))  # Private DNS of the EC2 host
    instance_private_ip = db.Column(db.String(255))  # Private IP of the EC2 host
    instance_id = db.Column(db.String(255))  # Instance ID of the EC2 host
    instance_type = db.Column(
        db.String(255), nullable=False
    )  # Instance type of the EC2 host
    instance_base_os = db.Column(
        db.String(255), nullable=False
    )  # Base OS of the EC2 host
    os_family = db.Column(
        db.String(255), nullable=False
    )  # OS Family (Windows or Linux)
    support_hibernation = db.Column(
        db.Boolean, nullable=False
    )  # If EC2 host has hibernation turned on/off

    # Relationships
    software_stack = relationship(
        "SoftwareStacks", back_populates="virtual_desktop_sessions"
    )

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class SoftwareStacks(db.Model):
    __tablename__ = "software_stacks"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stack_name = db.Column(db.Text, nullable=False)

    # AMI Information
    ami_id = db.Column(db.String(255), nullable=False)
    ami_arch = db.Column(db.String(255), nullable=False)
    ami_base_os = db.Column(db.String(255), nullable=False)
    ami_root_disk_size = db.Column(db.Integer)

    # Stack Info
    created_on = db.Column(db.DateTime)
    created_by = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    deactivated_by = db.Column(db.String(255))
    deactivated_on = db.Column(db.DateTime)
    thumbnail = db.Column(db.Text, nullable=False)
    description = db.Column(
        db.String(500)
    )  # Admin can add useful information to the user, such as who own the software stack or support email
    virtual_desktop_profile_id = Column(
        Integer, ForeignKey("virtual_desktop_profiles.id"), nullable=False
    )
    # Allow for launch tenancy and host information to be saved with the AMI registration
    # https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-dedicated-instances.html
    # launch_host is nullable since it is not required (untargeted method)
    launch_tenancy = db.Column(db.String(255), nullable=False)
    launch_host = db.Column(db.String(255), nullable=True)
    os_family = db.Column(
        db.String(255), nullable=False
    )  # OS Family (Windows or Linux)

    # Relationships
    profile_ids = relationship(
        "VirtualDesktopProfiles", back_populates="software_stacks"
    )

    virtual_desktop_sessions = relationship(
        "VirtualDesktopSessions", back_populates="software_stack"
    )
    projects = relationship(
        "Projects",
        secondary=project_software_stack_association,
        back_populates="software_stacks",
    )

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class VirtualDesktopProfiles(db.Model):
    __tablename__ = "virtual_desktop_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    profile_name = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False)
    pattern_allowed_instance_types = db.Column(
        db.String(500), nullable=False
    )  # csv of instance type,family allowed. Wildcard supported
    allowed_instance_types = db.Column(
        db.Text, nullable=False
    )  # json of all instance types based on pattern, grouped by arch
    allowed_subnet_ids = db.Column(
        db.String(500), nullable=False
    )  # csv of approved subnet ids. Wildcard supported
    max_root_size = db.Column(db.Integer, nullable=False)  # max root size in GB

    software_stacks = relationship("SoftwareStacks", back_populates="profile_ids")

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class Projects(db.Model):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_on = db.Column(db.DateTime)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    project_name = db.Column(db.String(255), nullable=False)
    allowed_users = db.Column(db.Text, nullable=False)
    allowed_groups = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    description = db.Column(db.String(500))

    # Relationships
    software_stacks = relationship(
        "SoftwareStacks",
        secondary=project_software_stack_association,
        back_populates="projects",
    )

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
