import logging
import config
from flask import render_template, Blueprint, request, redirect, session, flash, Response
from requests import get
from decorators import login_required
import boto3
from models import db, WindowsDCVSessions,AmiList
import uuid
import random
import string
import base64
from datetime import datetime, timezone
import pytz
import read_secretmanager
from botocore.exceptions import ClientError
import re
import os
import json
import dcv_cloudformation_builder
from cryptography.fernet import Fernet

remote_desktop_windows = Blueprint('remote_desktop_windows', __name__, template_folder='templates')
client_ec2 = boto3.client("ec2")
client_lambda = boto3.client("lambda")
client_cfn = boto3.client("cloudformation")
logger = logging.getLogger("application")

def get_ami_info():
    ami_info = {}
    for session_info in AmiList.query.filter_by(is_active=True, ami_type="windows").all():
        ami_info[session_info.ami_label] = session_info.ami_id
    return ami_info

def encrypt(message):
    key = config.Config.DCV_TOKEN_SYMMETRIC_KEY
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message.encode("utf-8"))


def can_launch_instance(launch_parameters):
    try:
        client_ec2.run_instances(
            BlockDeviceMappings=[
                {
                    'DeviceName': '/dev/sda1',
                    'Ebs': {
                        'DeleteOnTermination': True,
                        'VolumeSize': 30 if launch_parameters["disk_size"] is False else int(launch_parameters["disk_size"]),
                        'VolumeType': 'gp2',
                        'Encrypted': True
                    },
                },
            ],
            MaxCount=1,
            MinCount=1,
            SecurityGroupIds=[launch_parameters["security_group_id"]],
            InstanceType=launch_parameters["instance_type"],
            IamInstanceProfile={'Arn': launch_parameters["instance_profile"]},
            SubnetId=random.choice(launch_parameters["soca_private_subnets"]),
            UserData=launch_parameters["user_data"],
            ImageId=launch_parameters["image_id"],
            DryRun=True,
            HibernationOptions={'Configured': launch_parameters["hibernate"]},
        )

    except ClientError as err:
        if err.response['Error'].get('Code') == 'DryRunOperation':
            return True
        else:
            return "Dry run failed. Unable to launch capacity due to: {}".format(err)


def get_host_info(tag_uuid, cluster_id):
    host_info = {}
    token = True
    next_token = ''
    while token is True:
        response = client_ec2.describe_instances(
            Filters=[
                {
                    'Name': 'tag:soca:DCVSessionUUID',
                    'Values': [tag_uuid]
                },
                {
                    "Name": "tag:soca:ClusterId",
                    "Values": [cluster_id]
                },
                {
                    "Name": "tag:soca:DCVSystem",
                    "Values": ["windows"]
                }
            ],
            MaxResults=1000,
            NextToken=next_token,
        )

        try:
            next_token = response['NextToken']
        except KeyError:
            token = False

        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                if instance['PrivateDnsName'].split('.')[0]:
                    host_info["private_dns"] = instance['PrivateDnsName'].split('.')[0]
                    host_info["private_ip"] = instance['PrivateIpAddress']
                    host_info["instance_id"] = instance['InstanceId']
                    host_info["status"] = instance['State']['Name']

    return host_info


@remote_desktop_windows.route('/remote_desktop_windows', methods=['GET'])
@login_required
def index():
    user_sessions = {}
    for session_info in WindowsDCVSessions.query.filter_by(user=session["user"], is_active=True).all():
        session_number = session_info.session_number
        session_state = session_info.session_state
        session_local_admin_password = session_info.session_local_admin_password
        tag_uuid = session_info.tag_uuid
        session_name = session_info.session_name
        session_host_private_dns = session_info.session_host_private_dns
        session_token = session_info.session_token
        session_instance_type = session_info.session_instance_type
        session_instance_id = session_info.session_instance_id
        session_schedule = {"monday": str(session_info.schedule_monday_start) + "-" + str(session_info.schedule_monday_stop),
                            "tuesday": str(session_info.schedule_tuesday_start) + "-" + str(session_info.schedule_tuesday_stop),
                            "wednesday": str(session_info.schedule_wednesday_start) + "-" + str(session_info.schedule_wednesday_stop),
                            "thursday": str(session_info.schedule_thursday_start) + "-" + str(session_info.schedule_thursday_stop),
                            "friday": str(session_info.schedule_friday_start) + "-" + str(session_info.schedule_friday_stop),
                            "saturday": str(session_info.schedule_saturday_start) + "-" + str(session_info.schedule_saturday_stop),
                            "sunday": str(session_info.schedule_sunday_start) + "-" + str(session_info.schedule_sunday_stop)
                            }
        support_hibernation = session_info.support_hibernation
        dcv_authentication_token = session_info.dcv_authentication_token

        session_id = session_info.session_id
        stack_name = str(read_secretmanager.get_soca_configuration()["ClusterId"] + "-" + session_name + "-" + session["user"])
        host_info = get_host_info(tag_uuid, read_secretmanager.get_soca_configuration()["ClusterId"])
        logger.info(f"Host Info {host_info}")
        if not host_info:
            try:
                check_stack = client_cfn.describe_stacks(StackName=stack_name)
                logger.info(f"Host Info check_stack {check_stack}")
                if check_stack['Stacks'][0]['StackStatus'] in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED']:
                    logger.info(f"Host Info DEACTIVATE")
                    # no host detected, session no longer active
                    session_info.is_active = False
                    session_info.deactivated_on = datetime.utcnow()
                    db.session.commit()
            except Exception as err:
                logger.error(f"Error checking CFN stack {stack_name} due to {err}")
                session_info.is_active = False
                session_info.deactivated_on = datetime.utcnow()
                db.session.commit()
        else:
            # detected EC2 host for the session
            if not dcv_authentication_token:
                session_info.session_host_private_dns = host_info["private_dns"]
                session_info.session_host_private_ip = host_info["private_ip"]
                session_info.session_instance_id = host_info["instance_id"]
                authentication_data = json.dumps({"system": "windows",
                                                  "session_instance_id": host_info["instance_id"],
                                                  "session_token": session_token,
                                                  "session_user": session["user"]})
                session_authentication_token = base64.b64encode(encrypt(authentication_data)).decode("utf-8")
                session_info.dcv_authentication_token = session_authentication_token
                db.session.commit()

        if "status" not in host_info.keys():
            try:
                check_stack = client_cfn.describe_stacks(StackName=stack_name)
                logger.info(f"Host Info check_stack {check_stack}")
                if check_stack['Stacks'][0]['StackStatus'] in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED']:
                    logger.info(f"Host Info DEACTIVATE")
                    # no host detected, session no longer active
                    session_info.is_active = False
                    session_info.deactivated_on = datetime.utcnow()
                    db.session.commit()

            except Exception as err:
                logger.error(f"Error checking CFN stack {stack_name} due to {err}")
                session_info.is_active = False
                session_info.deactivated_on = datetime.utcnow()
                db.session.commit()
        else:
            if host_info["status"] in ["stopped", "stopping"] and session_state != "stopped":
                session_state = "stopped"
                session_info.session_state = "stopped"
                db.session.commit()

        if session_state == "pending" and session_host_private_dns is not False:
            check_dcv_state = get('https://' + read_secretmanager.get_soca_configuration()['LoadBalancerDNSName'] + '/' + session_host_private_dns + '/',
                                  allow_redirects=False,
                                  verify=False)

            logger.info("Checking {} for {} and received status {} ".format('https://' + read_secretmanager.get_soca_configuration()['LoadBalancerDNSName'] + '/' + session_host_private_dns + '/',
                                                                            session_info,
                                                                            check_dcv_state.status_code))

            if check_dcv_state.status_code == 200:
                session_info.session_state = "running"
                db.session.commit()

        user_sessions[session_number] = {
            "url": 'https://' + read_secretmanager.get_soca_configuration()['LoadBalancerDNSName'] + '/' + session_host_private_dns +'/',
            "session_local_admin_password": session_local_admin_password,
            "session_state": session_state,
            "session_authentication_token": dcv_authentication_token,
            "session_id": session_id,
            "session_name": session_name,
            "session_instance_id": session_instance_id,
            "session_instance_type": session_instance_type,
            "tag_uuid": tag_uuid,
            "support_hibernation": support_hibernation,
            "session_schedule": session_schedule}

    max_number_of_sessions = config.Config.DCV_WINDOWS_SESSION_COUNT
    # List of instances not available for DCV. Adjust as needed
    blacklist = config.Config.DCV_BLACKLIST_INSTANCE_TYPE
    all_instances_available = client_ec2._service_model.shape_for('InstanceType').enum
    all_instances = [p for p in all_instances_available if not any(substr in p for substr in blacklist)]
    try:
        tz = pytz.timezone(config.Config.TIMEZONE)
    except pytz.exceptions.UnknownTimeZoneError:
        flash("Timezone {} configured by the admin does not exist. Defaulting to UTC. Refer to https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for a full list of supported timezones".format(config.Config.TIMEZONE))
        tz = pytz.timezone("UTC")

    server_time = (datetime.now(timezone.utc)).astimezone(tz).strftime("%Y-%m-%d (%A) %H:%M")

    return render_template('remote_desktop_windows.html',
                           user=session["user"],
                           user_sessions=user_sessions,
                           hibernate_idle_session=config.Config.DCV_WINDOWS_HIBERNATE_IDLE_SESSION,
                           stop_idle_session=config.Config.DCV_WINDOWS_STOP_IDLE_SESSION,
                           terminate_stopped_session=config.Config.DCV_WINDOWS_TERMINATE_STOPPED_SESSION,
                           terminate_session=config.Config.DCV_WINDOWS_TERMINATE_STOPPED_SESSION,
                           allow_instance_change=config.Config.DCV_WINDOWS_ALLOW_INSTANCE_CHANGE,
                           page='remote_desktop',
                           server_time=server_time,
                           server_timezone_human=config.Config.TIMEZONE,
                           all_instances=all_instances,
                           max_number_of_sessions=max_number_of_sessions,
                           ami_list=get_ami_info())


@remote_desktop_windows.route('/remote_desktop_windows/create', methods=['POST'])
@login_required
def create():
    parameters = {}
    for parameter in ["instance_type", "disk_size", "session_number", "session_name", "instance_ami", "hibernate", "subnet_id"]:
        if not request.form[parameter]:
            parameters[parameter] = False
        else:
            if request.form[parameter].lower() in ["yes", "true"]:
                parameters[parameter] = True
            elif request.form[parameter].lower() in ["no", "false"]:
                parameters[parameter] = False
            else:
                parameters[parameter] = request.form[parameter]

    session_uuid = str(uuid.uuid4())
    region = os.environ["AWS_DEFAULT_REGION"]
    instance_type = parameters["instance_type"]
    soca_configuration = read_secretmanager.get_soca_configuration()
    instance_profile = soca_configuration["ComputeNodeInstanceProfileArn"]
    security_group_id = soca_configuration["ComputeNodeSecurityGroup"]
    if parameters["subnet_id"] is not False:
        soca_private_subnets = [parameters["subnet_id"]]
    else:
        soca_private_subnets = [soca_configuration["PrivateSubnet1"],
                            soca_configuration["PrivateSubnet2"],
                            soca_configuration["PrivateSubnet3"]]

    # sanitize session_name, limit to 255 chars
    if parameters["session_name"] is False:
        session_name = 'WindowsDesktop' + str(parameters["session_number"])
    else:
        session_name = re.sub(r'\W+', '', parameters["session_name"])[:255]
        if session_name == "":
            # handle case when session name specified by user only contains invalid char
            session_name = 'WindowsDesktop' + str(parameters["session_number"])

    # Official DCV AMI
    # https://aws.amazon.com/marketplace/pp/B07TVL513S + https://aws.amazon.com/marketplace/pp/B082HYM34K
    # Non graphics is everything but g3/g4
    if parameters["instance_ami"] == "base":
        dcv_windows_ami = config.Config.DCV_WINDOWS_AMI
        if instance_type.startswith("g"):
            if region not in dcv_windows_ami["graphics"].keys() and parameters["instance_ami"] is False:
                flash("Sorry, Windows Desktop is not available on your AWS region. Base AMI are only available on {}".format(dcv_windows_ami["graphics"].keys()),"error")
                return redirect("/remote_desktop_windows")
            else:
                image_id = dcv_windows_ami["graphics"][region]
        else:
            if region not in dcv_windows_ami["non-graphics"].keys() and parameters["instance_ami"] is False:
                flash("Sorry, Windows Desktop is not available on your AWS region. Base AMI are only available on {}".format(dcv_windows_ami["non-graphics"].keys()), "error")

                return redirect("/remote_desktop_windows")
            else:
                image_id = dcv_windows_ami["non-graphics"][region]
    else:
        image_id = parameters["instance_ami"]
        if not image_id.startswith("ami-"):
            flash("AMI selectioned {} does not seems to be valid. Must start with ami-<id>".format(image_id), "error")
            return redirect("/remote_desktop_windows")

    digits = ([random.choice(''.join(random.choice(string.digits) for _ in range(10))) for _ in range(3)])
    uppercase = ([random.choice(''.join(random.choice(string.ascii_uppercase) for _ in range(10))) for _ in range(3)])
    lowercase = ([random.choice(''.join(random.choice(string.ascii_lowercase) for _ in range(10))) for _ in range(3)])
    pw = digits + uppercase + lowercase
    session_local_admin_password = ''.join(random.sample(pw, len(pw)))
    user_data_script = open("/apps/soca/"+soca_configuration["ClusterId"]+"/cluster_node_bootstrap/windows/ComputeNodeInstallDCVWindows.ps", "r")
    user_data = user_data_script.read()
    user_data_script.close()
    user_data = user_data.replace("%SOCA_LOCAL_ADMIN_PASSWORD%", session_local_admin_password)
    user_data = user_data.replace("%SOCA_SchedulerPrivateIP%", soca_configuration['SchedulerPrivateIP'] + ":" + str(config.Config.FLASK_PORT))
    user_data = user_data.replace("%SOCA_LoadBalancerDNSName%", soca_configuration['LoadBalancerDNSName'])
    user_data = user_data.replace("%SOCA_LOCAL_USER%", session["user"])

    if config.Config.DCV_WINDOWS_AUTOLOGON is True:
        user_data = user_data.replace("%SOCA_WINDOWS_AUTOLOGON%", "true")
    else:
        user_data = user_data.replace("%SOCA_WINDOWS_AUTOLOGON%", "false")



    check_hibernation_support = client_ec2.describe_instance_types(
        InstanceTypes=[instance_type],
        Filters=[
            {"Name": "hibernation-supported",
             "Values": ["true"]}]
    )
    logger.info("Checking in {} support Hibernation : {}".format(instance_type, check_hibernation_support))
    if len(check_hibernation_support["InstanceTypes"]) == 0:
        if config.Config.DCV_FORCE_INSTANCE_HIBERNATE_SUPPORT is True:
            flash("Sorry your administrator limited <a href='https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/Hibernate.html#hibernating-prerequisites' target='_blank'>DCV to instances that support hibernation mode</a> <br> Please choose a different type of instance.")
            return redirect("/remote_desktop_windows")
        else:
            hibernate_support = False
    else:
        hibernate_support = True

    if parameters["hibernate"] and not hibernate_support:
        flash("Sorry you have selected {} with hibernation support, but this instance type does not support it. Either disable hibernation support or pick a different instance type".format(instance_type), "error")
        return redirect("/remote_desktop_windows")

    launch_parameters = {"security_group_id": security_group_id,
                         "instance_profile": instance_profile,
                         "instance_type": instance_type,
                         "soca_private_subnets": soca_private_subnets,
                         "user_data": user_data,
                         "image_id": image_id,
                         "session_name": session_name,
                         "session_uuid": session_uuid,
                         "base_os": "windows",
                         "disk_size": parameters["disk_size"],
                         "cluster_id": soca_configuration["ClusterId"],
                         "hibernate": parameters["hibernate"],
                         "user": session["user"],
                         "DefaultMetricCollection": True if soca_configuration["DefaultMetricCollection"] == "true" else False,
                         "SolutionMetricLambda": soca_configuration['SolutionMetricLambda'],
                         "ComputeNodeInstanceProfileArn": soca_configuration["ComputeNodeInstanceProfileArn"]
                         }
    dry_run_launch = can_launch_instance(launch_parameters)
    if dry_run_launch is True:
        launch_template = dcv_cloudformation_builder.main(**launch_parameters)
        if launch_template["success"] is True:
            cfn_stack_name = str(launch_parameters["cluster_id"] + "-" + launch_parameters["session_name"] + "-" + launch_parameters["user"])
            cfn_stack_tags = [{"Key": "soca:JobName", "Value": str(launch_parameters["session_name"])},
                              {"Key": "soca:JobOwner", "Value": str(session["user"])},
                              {"Key": "soca:JobProject", "Value": "desktop"},
                              {"Key": "soca:ClusterId", "Value": str(launch_parameters["cluster_id"])},
                              {"Key": "soca:NodeType", "Value": "dcv"},
                              {"Key": "soca:DCVSystem", "Value": "windows"}]
            try:
                client_cfn.create_stack(
                    StackName=cfn_stack_name,
                    TemplateBody=launch_template["output"],
                    Tags=cfn_stack_tags)
            except Exception as e:
                logger.error(f"Error while trying to provision {cfn_stack_name} due to {e}")
                flash(f"Error while trying to provision {cfn_stack_name} due to {e}")
                return redirect("/remote_desktop_windows")
        else:
            flash(launch_template["output"], "error")
            return redirect("/remote_desktop_windows")
    else:
        flash(dry_run_launch, "error")
        return redirect("/remote_desktop_windows")

    flash("Your session has been initiated. It will be ready within 10 minutes.", "success")
    new_session = WindowsDCVSessions(user=session["user"],
                                     session_number=parameters["session_number"],
                                     session_name=session_name,
                                     session_state="pending",
                                     session_host_private_dns=False,
                                     session_host_private_ip=False,
                                     session_instance_type=instance_type,
                                     dcv_authentication_token=None,
                                     session_local_admin_password=session_local_admin_password,
                                     session_id="console",
                                     tag_uuid=session_uuid,
                                     session_token=str(uuid.uuid4()),
                                     is_active=True,
                                     support_hibernation=parameters["hibernate"],
                                     created_on=datetime.utcnow(),
                                     schedule_monday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE_START,
                                     schedule_tuesday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE_START,
                                     schedule_wednesday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE_START,
                                     schedule_thursday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE_START,
                                     schedule_friday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE_START,
                                     schedule_saturday_start=0,
                                     schedule_sunday_start=0,
                                     schedule_monday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE_STOP,
                                     schedule_tuesday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE_STOP,
                                     schedule_wednesday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE_STOP,
                                     schedule_thursday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE_STOP,
                                     schedule_friday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE_STOP,
                                     schedule_saturday_stop=0,
                                     schedule_sunday_stop=0,

                                     )
    db.session.add(new_session)
    db.session.commit()
    return redirect("/remote_desktop_windows")


@remote_desktop_windows.route('/remote_desktop_windows/delete', methods=['GET'])
@login_required
def delete():
    dcv_session = request.args.get("session", None)
    action = request.args.get("action", None)
    if action not in ["terminate", "stop", "hibernate"]:
        flash("action must be either terminate, stop or hibernate")
        return redirect("/remote_desktop_windows")

    if dcv_session is None:
        flash("Invalid graphical session ID", "error")
        return redirect("/remote_desktop_windows")

    check_session = WindowsDCVSessions.query.filter_by(user=session["user"],
                                                       session_number=dcv_session,
                                                       is_active=True).first()
    if check_session:
        instance_id = check_session.session_instance_id
        session_name = check_session.session_name
        if action == "hibernate":
            # Hibernate instance
            try:
                client_ec2.stop_instances(InstanceIds=[instance_id], Hibernate=True, DryRun=True)
            except ClientError as e:
                if e.response['Error'].get('Code') == 'DryRunOperation':
                    client_ec2.stop_instances(InstanceIds=[instance_id], Hibernate=True)
                    check_session.session_state = "stopped"
                    db.session.commit()
                else:
                    flash("Unable to hibernate instance ({}) due to {}".format(instance_id, e), "error")

        elif action == "stop":
            # Stop Instance
            try:
                client_ec2.stop_instances(InstanceIds=[instance_id], DryRun=True)
            except ClientError as e:
                if e.response['Error'].get('Code') == 'DryRunOperation':
                    client_ec2.stop_instances(InstanceIds=[instance_id])
                    check_session.session_state = "stopped"
                    db.session.commit()
                else:
                    flash("Unable to Stop instance ({}) due to {}".format(instance_id, e), "error")

        else:
            # Terminate instance
            stack_name = str(read_secretmanager.get_soca_configuration()["ClusterId"] + "-" + session_name + "-" + session["user"])
            try:
                client_cfn.delete_stack(StackName=stack_name)
                flash("Your graphical session is about to be terminated.", "success")
                check_session.is_active = False
                check_session.deactivated_on = datetime.utcnow()
                db.session.commit()
                return redirect("/remote_desktop_windows")
            except ClientError as e:
                flash("Unable to delete associated stack ({}) due to {}".format(stack_name, e), "error")

    else:
        flash("Unable to retrieve this session", "error")

    return redirect("/remote_desktop_windows")


@remote_desktop_windows.route('/remote_desktop_windows/restart', methods=['GET'])
@login_required
def restart_from_hibernate():
    dcv_session = request.args.get("session", None)
    if dcv_session is None:
        flash("Invalid graphical session", "error")
        return redirect("/remote_desktop_windows")

    check_session = WindowsDCVSessions.query.filter_by(user=session["user"],
                                                       session_number=dcv_session,
                                                       session_state="stopped",
                                                       is_active=True).first()
    if check_session:
        instance_id = check_session.session_instance_id
        try:
            client_ec2.start_instances(InstanceIds=[instance_id], DryRun=True)
        except ClientError as e:
            if e.response['Error'].get('Code') == 'DryRunOperation':
                try:
                    client_ec2.start_instances(InstanceIds=[instance_id])
                    check_session.session_state = "pending"
                    db.session.commit()
                except Exception as err:
                    flash("Please wait a little bit before restarting this session as the underlying resource is still being stopped.", "error")

            else:
                flash("Unable to restart instance ({}) due to {}".format(instance_id, e), "error")
    else:
        flash("Unable to retrieve this session", "error")

    return redirect("/remote_desktop_windows")

@remote_desktop_windows.route('/remote_desktop_windows/modify', methods=['POST'])
@login_required
def modify():
    dcv_session = None if not "session_number" in request.form else request.form["session_number"]
    new_instance_type = None if not "instance_type" in request.form else request.form["instance_type"]
    if dcv_session is None:
        flash("Invalid graphical session", "error")
        return redirect("/remote_desktop_windows")

    if new_instance_type is None:
        flash("Invalid new EC2 instance type", "error")
        return redirect("/remote_desktop_windows")

    blacklist = config.Config.DCV_BLACKLIST_INSTANCE_TYPE
    all_instances_available = client_ec2._service_model.shape_for('InstanceType').enum
    all_instances = [p for p in all_instances_available if not any(substr in p for substr in blacklist)]
    if new_instance_type not in all_instances:
        flash("This EC2 instance type is not authorized", "error")
        return redirect("/remote_desktop_windows")

    check_session = WindowsDCVSessions.query.filter_by(user=session["user"],
                                                       session_number=dcv_session,
                                                       session_state="stopped",
                                                       is_active=True).first()
    if check_session:
        instance_id = check_session.session_instance_id
        try:
            client_ec2.modify_instance_attribute(InstanceId=instance_id,
                                                 InstanceType={'Value': new_instance_type},
                                                 DryRun=True)
        except ClientError as e:
            if e.response['Error'].get('Code') == 'DryRunOperation':
                try:
                    client_ec2.modify_instance_attribute(InstanceId=instance_id,
                                                         InstanceType={'Value': new_instance_type})
                    check_session.session_instance_type = new_instance_type
                    db.session.commit()
                    flash("Your EC2 instance has been updated successfully to: {}".format(new_instance_type), "success")
                except ClientError as err:
                    if "not supported for instances with hibernation configured." in err.response['Error'].get('Code'):
                        flash("Your intance has been started with hibernation enabled. You cannot change the instance type. Start a new session with Hibernation disabled if you want to be able to change your instance type. ", "error")
                    else:
                        flash("Unable to modify EC2 instance type due to {}".format(err), "error")
            else:
                flash("Unable to modify instance ({}) due to {}".format(instance_id, e), "error")
    else:
        flash("Unable to retrieve this session. Either session does not exist or is not stopped", "error")

    return redirect("/remote_desktop_windows")


@remote_desktop_windows.route('/remote_desktop_windows/schedule', methods=['POST'])
@login_required
def schedule():
    week_days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
    schedule = {}
    session_number = None if "session_number" not in request.form else request.form["session_number"]
    error = False
    if not session_number:
        flash("Session Number is missing", "error")
        logger.error("Session number is missing {}".format(request.form))
        return redirect("/remote_desktop_windows")

    for day in week_days:
        schedule_name = "schedule-" + day + "-" + session_number
        if schedule_name not in request.form.keys():
            error = "Unable to retrieve schedule for {}".format(day)
        else:
            schedule_value = request.form[schedule_name].split("-")
            if len(schedule_value) == 2:
                try:
                    start_time = int(schedule_value[0])
                    end_time = int(schedule_value[1])
                    if end_time < start_time:
                        error = "End time ({}) must be greater than start time ({})".format(end_time,start_time)
                    elif end_time > 1440:
                        error = "End Time ({}) cannot be greater than 1440 (12PM)".format(end_time)
                    elif start_time < 0:
                        error = "Start time ({}) must be greater than 0 (12AM)".format(start_time)
                    elif start_time == end_time:
                        schedule[day] = "0-0"  # no run
                    else:
                        schedule[day] = str(start_time) + "-" + str(end_time)
                except ValueError:
                    error = "Schedule must use number1-number2 format where number1 and number2 are valid integer : ".format(schedule_value)
            else:
                error = "Schedule values must be number1-number2 format and not {}".format(schedule_value)

    if error is not False:
        flash(error, "error")
        logger.error(error)
        return redirect("/remote_desktop_windows")

    else:
        check_session = WindowsDCVSessions.query.filter_by(user=session["user"],
                                                           session_number=session_number,
                                                           is_active=True).first()
        if check_session:
            check_session.schedule_monday_start = schedule["monday"].split("-")[0]
            check_session.schedule_monday_stop = schedule["monday"].split("-")[1]
            check_session.schedule_tuesday_start = schedule["tuesday"].split("-")[0]
            check_session.schedule_tuesday_stop = schedule["tuesday"].split("-")[1]
            check_session.schedule_wednesday_start = schedule["wednesday"].split("-")[0]
            check_session.schedule_wednesday_stop = schedule["wednesday"].split("-")[1]
            check_session.schedule_thursday_start = schedule["thursday"].split("-")[0]
            check_session.schedule_thursday_stop = schedule["thursday"].split("-")[1]
            check_session.schedule_friday_start = schedule["friday"].split("-")[0]
            check_session.schedule_friday_stop = schedule["friday"].split("-")[1]
            check_session.schedule_saturday_start = schedule["saturday"].split("-")[0]
            check_session.schedule_saturday_stop = schedule["saturday"].split("-")[1]
            check_session.schedule_sunday_start = schedule["sunday"].split("-")[0]
            check_session.schedule_sunday_stop = schedule["sunday"].split("-")[1]
            db.session.commit()
            flash("Your session schedule has been updated correctly", "success")
            return redirect("/remote_desktop_windows")

        else:
            flash("Unable to retrieve this session. This session may have been terminated.", "error")
            return redirect("/remote_desktop_windows")







@remote_desktop_windows.route('/remote_desktop_windows/client', methods=['GET'])
@login_required
def generate_client():
    dcv_session = request.args.get("session", None)
    if dcv_session is None:
        flash("Invalid graphical sessions", "error")
        return redirect("/remote_desktop_windows")

    check_session = WindowsDCVSessions.query.filter_by(user=session["user"],
                                                       session_number=dcv_session,
                                                       is_active=True).first()
    if check_session:
        session_file = '''
[version]
format=1.0

[connect]
host=''' + read_secretmanager.get_soca_configuration()['LoadBalancerDNSName'] + '''
port=443
sessionid=console
user=''' + str(session["user"]) + '''
authToken='''+check_session.dcv_authentication_token+'''
weburlpath=/''' + check_session.session_host_private_dns + '''
'''
        return Response(
            session_file,
            mimetype='text/txt',
            headers={'Content-disposition': 'attachment; filename=' + session['user'] + '_soca_' + str(dcv_session) + '.dcv'})

    else:
        flash("Unable to retrieve this session. This session may have been terminated.", "error")
        return redirect("/remote_desktop_windows")

