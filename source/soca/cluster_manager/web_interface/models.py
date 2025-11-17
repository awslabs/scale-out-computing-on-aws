# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import ENUM
from extensions import db
import datetime
from sqlalchemy import event
from flask import has_request_context, session, request
from sqlalchemy.sql import func
from sqlalchemy.sql import exists, and_, or_, not_
from typing import List, Set, Type
from sqlalchemy.orm import Session

SessionState = ENUM("pending", "running", "stopped", "error", name="session_state_enum")
OSFamily = ENUM("linux", "windows", name="os_family")
MembershipState = ENUM("allow", "deny", name="membership_state")
IdentityName = ENUM("user", "group", name="identityName")


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

project_target_node_software_stack_association = Table(
    "project_target_node_software_stack",
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
        ForeignKey("target_node_software_stacks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

user_data_target_node_software_stack_association = Table(
    "target_node_user_data_software_stack",
    db.Model.metadata,
    db.Column(
        "template_id",
        db.Integer,
        ForeignKey("target_node_user_data.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "target_node_software_stack_id",
        db.Integer,
        ForeignKey("target_node_software_stacks.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

project_application_profile_association = Table(
    "project_application_profile",
    db.Model.metadata,
    db.Column(
        "project_id",
        db.Integer,
        ForeignKey("projects.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    db.Column(
        "application_profile_id",
        db.Integer,
        ForeignKey("application_profiles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class BaseModel(db.Model):
    __abstract__ = True
    updated_by = db.Column(db.String(255))
    updated_on = db.Column(db.DateTime, default=func.now(), onupdate=func.now())

    def __repr__(self):
        pk_names = [key.name for key in self.__mapper__.primary_key]
        pk_values = ", ".join(f"{name}={getattr(self, name)}" for name in pk_names)
        return f"<{self.__class__.__name__} {pk_values}>"

    def as_dict(self, exclude_columns=None):
        exclude_columns = set(exclude_columns or [])
        return {
            c.name: getattr(self, c.name)
            for c in self.__table__.columns
            if c.name not in exclude_columns
        }


@event.listens_for(BaseModel, "before_update", propagate=True)
def receive_before_update(mapper, connection, target):
    if has_request_context():
        if "user" in session:
            target.updated_by = session["user"]
        elif request.headers.get("X-SOCA-USER"):
            target.updated_by = request.headers.get("X-SOCA-USER")
        else:
            target.updated_by = "UNKNOWN"
    else:
        target.updated_by = "UNKNOWN"


class ApiKeys(BaseModel):
    __tablename__ = "api_keys"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False)
    scope = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    deactivated_on = db.Column(db.DateTime)


class ApplicationProfiles(BaseModel):
    __tablename__ = "application_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_by = db.Column(db.String(255), nullable=False)
    profile_name = db.Column(db.String(255), nullable=False, unique=True)
    profile_form = db.Column(db.Text, nullable=False)
    profile_job = db.Column(db.Text, nullable=False)
    profile_interpreter = db.Column(db.Text, nullable=False)
    profile_thumbnail = db.Column(db.Text, nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    deactivated_on = db.Column(db.DateTime)

    # Relationships
    projects = relationship(
        "Projects",
        secondary=project_application_profile_association,
        back_populates="application_profiles",
    )

    def as_dict(self, exclude_columns=None):
        result = super().as_dict(exclude_columns=exclude_columns)
        if self.projects:
            result["projects"] = [p.id for p in self.projects]
        else:
            result["projects"] = []

        return result


class VirtualDesktopSessions(BaseModel):
    __tablename__ = "virtual_desktop_sessions"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    is_active = db.Column(db.Boolean, nullable=False)  # If session is active or not
    created_on = db.Column(
        db.DateTime, nullable=False
    )  # Timestamp when session was created
    deactivated_on = db.Column(db.DateTime)  # Timestamp when session was deleted
    deactivated_by = db.Column(db.String(255))
    stack_name = db.Column(
        db.String(255), nullable=False
    )  # Name of the CloudFormation Stack
    session_uuid = db.Column(
        db.String(36), nullable=False, index=True
    )  # Manage EC2 tag soca:DCVSessionUUID as well as session ID
    session_name = db.Column(
        db.String(255), nullable=False
    )  # Session name specified by the user
    session_project = db.Column(db.String(255), nullable=False)  # Project
    session_state = db.Column(SessionState, nullable=False)
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
    session_owner = db.Column(
        db.String(255), nullable=False, index=True
    )  # Session owner
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
    os_family = db.Column(OSFamily, nullable=False)
    support_hibernation = db.Column(
        db.Boolean, nullable=False
    )  # If EC2 host has hibernation turned on/off

    # Relationships
    software_stack = relationship(
        "SoftwareStacks", back_populates="virtual_desktop_sessions"
    )


class SoftwareStacks(BaseModel):
    __tablename__ = "software_stacks"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stack_name = db.Column(db.Text, nullable=False)

    # AMI Information
    ami_id = db.Column(db.String(255), nullable=False)
    ami_arch = db.Column(db.String(255), nullable=False)
    ami_base_os = db.Column(db.String(255), nullable=False)
    ami_root_disk_size = db.Column(db.Integer, nullable=False)

    # Stack Info
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, index=True)
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
    os_family = db.Column(OSFamily, nullable=False)

    # Relationships
    profile = relationship("VirtualDesktopProfiles", back_populates="software_stacks")

    virtual_desktop_sessions = relationship(
        "VirtualDesktopSessions", back_populates="software_stack"
    )

    projects = relationship(
        "Projects",
        secondary=project_software_stack_association,
        back_populates="software_stacks",
    )

    def as_dict(self, exclude_columns=None, allowed_project_ids=None):
        exclude_columns = exclude_columns or []
        result = super().as_dict(exclude_columns=exclude_columns)

        if self.projects:
            filtered_projects = (
                [p for p in self.projects if p.id in allowed_project_ids]
                if allowed_project_ids
                else self.projects
            )

            result["projects"] = [
                {
                    column.name: getattr(p, column.name)
                    for column in p.__table__.columns
                    if column.name not in exclude_columns
                }
                for p in filtered_projects
            ]
            result["allowed_aws_budgets"] = list(
                dict.fromkeys(p.aws_budget for p in filtered_projects)
            )
            result["allowed_projects"] = list(
                dict.fromkeys(p.project_name for p in filtered_projects)
            )
        else:
            result["projects"] = []
            result["allowed_aws_budgets"] = []
            result["allowed_projects"] = []

        if self.profile:
            result["profile"] = {
                column.name: getattr(self.profile, column.name)
                for column in self.profile.__table__.columns
                if column.name not in exclude_columns
            }
        else:
            result["profile"] = {}

        return result


class VirtualDesktopProfiles(BaseModel):
    __tablename__ = "virtual_desktop_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    profile_name = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    description = db.Column(db.Text)
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

    software_stacks = relationship("SoftwareStacks", back_populates="profile")


class Projects(BaseModel):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    project_name = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    description = db.Column(db.String(500))
    aws_budget = db.Column(db.String(255))

    # Relationships
    software_stacks = relationship(
        "SoftwareStacks",
        secondary=project_software_stack_association,
        back_populates="projects",
    )

    target_node_software_stacks = relationship(
        "TargetNodeSoftwareStacks",
        secondary=project_target_node_software_stack_association,
        back_populates="projects",
    )

    application_profiles = relationship(
        "ApplicationProfiles",
        secondary=project_application_profile_association,
        back_populates="projects",
    )

    memberships = relationship("ProjectMemberships", back_populates="project")

    @property
    def allowed_users(self):
        return [
            m.identity_name
            for m in self.memberships
            if m.identity_type == "user" and m.state == "allow" and m.identity_name
        ]

    @property
    def denied_users(self):
        return [
            m.identity_name
            for m in self.memberships
            if m.identity_type == "user" and m.state == "deny" and m.identity_name
        ]

    @property
    def allowed_groups(self):
        return [
            m.identity_name
            for m in self.memberships
            if m.identity_type == "group" and m.state == "allow" and m.identity_name
        ]

    @property
    def denied_groups(self):
        return [
            m.identity_name
            for m in self.memberships
            if m.identity_type == "group" and m.state == "deny" and m.identity_name
        ]

    @classmethod
    def get_allowed_projects_for_user(
        cls, db_session: Session, user_name: str, groups: list
    ) -> Set[int]:
        """
        Returns set of allowed project IDs for a given user based on allow/deny rules
        matching their user identity or group memberships.
        """

        # DENY subquery: if there's *any* deny match for user_name, "*", or any group (checked by type)
        deny_subquery = (
            db_session.query(ProjectMemberships.project_id)
            .filter(
                ProjectMemberships.project_id == cls.id,
                or_(
                    # Deny matches for user
                    and_(
                        ProjectMemberships.identity_type == "user",
                        ProjectMemberships.identity_name.in_([user_name, "*"]),
                    ),
                    # Deny matches for groups
                    and_(
                        ProjectMemberships.identity_type == "group",
                        ProjectMemberships.identity_name.in_(groups),
                    ),
                ),
                ProjectMemberships.state == "deny",
            )
            .exists()
        )

        # ALLOW subquery: at least one allow match for user_name, "*", or any group
        allow_subquery = (
            db_session.query(ProjectMemberships.project_id)
            .filter(
                ProjectMemberships.project_id == cls.id,
                or_(
                    and_(
                        ProjectMemberships.identity_type == "user",
                        ProjectMemberships.identity_name.in_([user_name, "*"]),
                    ),
                    and_(
                        ProjectMemberships.identity_type == "group",
                        ProjectMemberships.identity_name.in_(groups),
                    ),
                ),
                ProjectMemberships.state == "allow",
            )
            .exists()
        )

        # Final query: only return active projects with no deny and at least one allow
        allowed_projects = (
            db_session.query(cls)
            .filter(
                cls.is_active == True,
                not_(deny_subquery),  # nothing denies access
                allow_subquery,  # something allows access
            )
            .all()
        )

        return {project.id for project in allowed_projects}


class ProjectMemberships(BaseModel):
    __tablename__ = "project_memberships"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)
    identity_type = db.Column(IdentityName, nullable=False)
    identity_name = db.Column(db.String(255), nullable=False)
    state = db.Column(MembershipState, nullable=False)
    project = relationship("Projects", back_populates="memberships")


class TargetNodeSessions(BaseModel):
    __tablename__ = "target_node_sessions"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    created_on = db.Column(db.DateTime, nullable=False)
    deactivated_on = db.Column(db.DateTime)  # Timestamp when session was deleted
    deactivated_by = db.Column(db.String(255))
    stack_name = db.Column(db.String(255))  # Name of the CloudFormation Stack
    session_name = db.Column(
        db.String(255), nullable=False
    )  # Session name specified by the user
    session_owner = db.Column(
        db.String(255), nullable=False, index=True
    )  # Session owner
    session_project = db.Column(db.String(255), nullable=False)  # Project
    session_state = db.Column(SessionState, nullable=False)
    session_state_latest_change_time = db.Column(db.DateTime, nullable=False)
    schedule = db.Column(db.Text, nullable=False)  #  session schedule
    session_thumbnail = db.Column(db.Text)  # session screenshot
    session_connection_instructions = db.Column(
        db.String(255), nullable=False
    )  # Helper for the end user: e.g: SSH to this machine using the `qnxuser` user via ssh qnxuser@<ip>
    session_uuid = db.Column(db.String(36), nullable=False, index=True)
    os_family = db.Column(OSFamily, nullable=False)
    # Instance Specific
    instance_state = db.Column(
        db.String(255), nullable=False
    )  # (pending/stopped/running)
    instance_private_ip = db.Column(db.String(255))  # Private IP of the EC2 host
    instance_private_dns = db.Column(db.String(255))  # Private IP of the EC2 host
    instance_id = db.Column(db.String(255))  # Instance ID of the EC2 host
    instance_type = db.Column(
        db.String(255), nullable=False
    )  # Instance type of the EC2 host

    # Relationships
    target_node_software_stack = relationship(
        "TargetNodeSoftwareStacks", back_populates="target_node_sessions"
    )
    target_node_software_stack_id = db.Column(
        db.Integer,
        db.ForeignKey("target_node_software_stacks.id", ondelete="CASCADE"),
        nullable=False,
    )


class TargetNodeProfiles(BaseModel):
    __tablename__ = "target_node_profiles"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    profile_name = db.Column(db.String(255), nullable=False)
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    description = db.Column(db.Text)
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

    target_node_software_stacks = relationship(
        "TargetNodeSoftwareStacks", back_populates="profile"
    )


class TargetNodeSoftwareStacks(BaseModel):
    __tablename__ = "target_node_software_stacks"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stack_name = db.Column(db.Text, nullable=False)

    # AMI Information
    ami_id = db.Column(db.String(255), nullable=False)
    ami_arch = db.Column(db.String(255), nullable=False)
    ami_root_disk_size = db.Column(db.Integer, nullable=False)
    ami_user_data_variables = db.Column(
        db.Text
    )  # CSV list of variable that will be replaced in the user data if specified: myvar1=myvalue,myvar2=myvalue2
    ami_connection_string = db.Column(
        db.Text, nullable=False
    )  # Optional, can specify information. Support variable substitution such as Instance Private IP etc ..
    os_family = db.Column(OSFamily, nullable=False)  # OS Family (Windows or Linux)
    # Stack Info
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    deactivated_by = db.Column(db.String(255))
    deactivated_on = db.Column(db.DateTime)
    thumbnail = db.Column(db.Text, nullable=False)
    description = db.Column(
        db.String(500)
    )  # Admin can add useful information to the user, such as who own the software stack or support email
    launch_tenancy = db.Column(db.String(255), nullable=False)
    launch_host = db.Column(db.String(255), nullable=True)

    # Parent Profile
    target_node_profile_id = Column(
        Integer, ForeignKey("target_node_profiles.id"), nullable=False
    )
    profile = relationship(
        "TargetNodeProfiles", back_populates="target_node_software_stacks"
    )

    # Parent User Data
    target_node_user_data_id = Column(
        Integer, ForeignKey("target_node_user_data.id"), nullable=False
    )

    user_data = relationship(
        "TargetNodeUserData", back_populates="target_node_software_stacks"
    )

    # Parent Sessions
    target_node_sessions = relationship(
        "TargetNodeSessions",
        back_populates="target_node_software_stack",
        cascade="all, delete-orphan",
    )

    # Parent Project
    projects = relationship(
        "Projects",
        secondary=project_target_node_software_stack_association,
        back_populates="target_node_software_stacks",
    )

    def as_dict(self, exclude_columns=None, allowed_project_ids=None):
        exclude_columns = exclude_columns or []
        result = super().as_dict(exclude_columns=exclude_columns)

        if self.projects:
            filtered_projects = (
                [p for p in self.projects if p.id in allowed_project_ids]
                if allowed_project_ids
                else self.projects
            )

            result["projects"] = [
                {
                    column.name: getattr(p, column.name)
                    for column in p.__table__.columns
                    if column.name not in exclude_columns
                }
                for p in filtered_projects
            ]
            result["allowed_aws_budgets"] = list(
                dict.fromkeys(p.aws_budget for p in filtered_projects)
            )
            result["allowed_projects"] = list(
                dict.fromkeys(p.project_name for p in filtered_projects)
            )
        else:
            result["projects"] = []
            result["allowed_aws_budgets"] = []
            result["allowed_projects"] = []

        if self.profile:
            result["profile"] = {
                column.name: getattr(self.profile, column.name)
                for column in self.profile.__table__.columns
                if column.name not in exclude_columns
            }
        else:
            result["profile"] = {}

        if self.user_data:
            user_data_fields = {
                "created_on": self.user_data.created_on,
                "created_by": self.user_data.created_by,
                "is_active": self.user_data.is_active,
                "template_name": self.user_data.template_name,
                "user_data": self.user_data.user_data,
                "description": self.user_data.description,
                "id": self.user_data.id,
            }
            result["user_data"] = {
                k: v for k, v in user_data_fields.items() if k not in exclude_columns
            }
        else:
            result["user_data"] = {}

        return result


class TargetNodeUserData(BaseModel):
    __tablename__ = "target_node_user_data"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_on = db.Column(db.DateTime, nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    deactivated_on = db.Column(db.DateTime)
    deactivated_by = db.Column(db.String(255))
    template_name = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, index=True)
    description = db.Column(db.String(500))
    user_data = db.Column(db.Text)
    target_node_software_stacks = relationship(
        "TargetNodeSoftwareStacks",
        back_populates="user_data",
        cascade="all, delete-orphan",
        foreign_keys=[TargetNodeSoftwareStacks.target_node_user_data_id],
    )

    def as_dict(self, exclude_columns=None):
        result = super().as_dict(exclude_columns=exclude_columns)
        if self.target_node_software_stacks:
            # statically defined to avoid circular dependency if calling target_node_software_stacks.as_dict() via python object
            result["target_node_software_stacks"] = [
                {
                    column.name: getattr(stack, column.name)
                    for column in stack.__table__.columns
                }
                for stack in self.target_node_software_stacks
            ]

        else:
            result["target_node_software_stacks"] = []

        return result
