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

import boto3
import logging
import os
import config
import re
from datetime import datetime, timezone, timedelta
import pytz
import json
import time
from dateutil.parser import parse
from models import db, WindowsDCVSessions, LinuxDCVSessions
from botocore.exceptions import ClientError
from models import db
from sqlalchemy import or_
import utils.aws.boto3_wrapper as utils_boto3

logger = logging.getLogger("soca_logger")

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_ssm = utils_boto3.get_boto(service_name="ssm").message
client_cloudformation = utils_boto3.get_boto(service_name="cloudformation").message


def now():
    try:
        tz = pytz.timezone(config.Config.TIMEZONE)
    except pytz.exceptions.UnknownTimeZoneError:
        logger.error(
            f"Timezone {config.Config.TIMEZONE} configured by the admin does not exist. Defaulting to UTC. Refer to https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for a full list of supported timezones"
        )
        tz = pytz.timezone("UTC")

    server_time = datetime.now(timezone.utc).astimezone(tz)
    return server_time


def retrieve_host(instances_info, instance_state):
    instance_ids = list(instances_info.keys())
    host_info = {}

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            f"retrieve_host(): Resolving Instances_info: {instances_info} - State: {instance_state}"
        )

    ec2_paginator = client_ec2.get_paginator("describe_instances")

    # Generate our filters
    if instances_info:
        filters = [
            {"Name": "instance-state-name", "Values": [instance_state]},
            {"Name": "instance-id", "Values": instance_ids},
            {
                "Name": "tag:soca:ClusterId",
                "Values": [os.environ["SOCA_CLUSTER_ID"]],
            },
            {
                "Name": "tag:soca:DCVSupportHibernate",
                "Values": ["true", "false"],
            },
            {"Name": "tag:soca:NodeType", "Values": ["dcv_node"]},
        ]
    else:
        filters = [
            {"Name": "instance-state-name", "Values": ["stopped"]},
            {
                "Name": "tag:soca:ClusterId",
                "Values": [os.environ["SOCA_CLUSTER_ID"]],
            },
            {
                "Name": "tag:soca:DCVSupportHibernate",
                "Values": ["true", "false"],
            },
            {"Name": "tag:soca:NodeType", "Values": ["dcv_node"]},
        ]

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"API request filters: {filters}")

    ec2_iterator = ec2_paginator.paginate(Filters=filters)

    for page in ec2_iterator:
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                session_uuid = False
                current_time = parse(page["ResponseMetadata"]["HTTPHeaders"]["date"])
                if instance_state == "stopped":
                    stopped_time = parse(
                        re.findall(r".*\((.*)\)", instance["StateTransitionReason"])[0]
                    )
                else:
                    stopped_time = False

                for _instance in reservation["Instances"]:
                    hibernate_enabled = False
                    stack_name = False
                    # When did the instance last launch?
                    # We use this to provide grace period for the instance that may be
                    # busy with startup operations
                    if _instance.get("LaunchTime", False) is not False:
                        _instance_launch_time = _instance.get("LaunchTime")
                    else:
                        _instance_launch_time = current_time

                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(
                            f"Instance {_instance['InstanceId']} last launched at {_instance_launch_time}"
                        )

                    for tag in _instance["Tags"]:
                        if tag["Key"] == "Name":
                            stack_name = tag["Value"]
                        if tag["Key"] == "soca:DCVSupportHibernate":
                            if tag["Value"] == "true":
                                hibernate_enabled = True
                        if tag["Key"] == "soca:DCVSessionUUID":
                            session_uuid = tag["Value"]

                    host_info[_instance["InstanceId"]] = {
                        "stopped_time": stopped_time,
                        "current_time": current_time,
                        "hibernate_enabled": hibernate_enabled,
                        "session_uuid": session_uuid,
                        "stack_name": stack_name if stack_name is not False else "",
                        "launch_time": _instance_launch_time,
                    }

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Host info returning: {host_info}")
    return host_info


def windows_auto_stop_instance(instances_to_check):
    # Automatically stop or hibernate (when possible) instances based on Idle time and CPU usage
    with db.app.app_context():
        logger.info(f"Scheduled Task: windows_auto_stop_instance {instances_to_check}")
        get_host_to_stop = retrieve_host(instances_to_check, "running")
        logger.info(
            f"windows_auto_stop_instance: List of Windows DCV hosts subject to stop/hibernate: {get_host_to_stop}"
        )

        for instance_id, instance_data in get_host_to_stop.items():
            if instance_data["hibernate_enabled"] is True:
                action = "hibernate"
                stop_instance_after = config.Config.DCV_WINDOWS_HIBERNATE_IDLE_SESSION
            else:
                action = "stop"
                stop_instance_after = config.Config.DCV_WINDOWS_STOP_IDLE_SESSION

            logger.info(
                f"windows_auto_stop_instance: Trying to {action} instance {instance_id} if idle for more than {stop_instance_after} hours and  CPU % is below {config.Config.DCV_IDLE_CPU_THRESHOLD}"
            )
            if stop_instance_after > 0:
                for _instance_id in get_host_to_stop.keys():
                    logger.info(f"Checking Instance ID: {instance_id}")
                    ssm_failed = False
                    ssm_list_command_loop = 0
                    powershell_commands = [
                        "$DCV_Describe_Session = Invoke-Expression \"& 'C:\\Program Files\\NICE\\DCV\\Server\\bin\\dcv' describe-session console -j\" | ConvertFrom-Json",
                        '$CPUAveragePerformanceLast10Secs = (GET-COUNTER -Counter "\\Processor(_Total)\\% Processor Time" -SampleInterval 2 -MaxSamples 5 |select -ExpandProperty countersamples | select -ExpandProperty cookedvalue | Measure-Object -Average).average',
                        "$output = @{}",
                        '$output["CPUAveragePerformanceLast10Secs"] = $CPUAveragePerformanceLast10Secs',
                        '$output["DCVCurrentConnections"] = $DCV_Describe_Session."num-of-connections"',
                        '$output["DCVCreationTime"] = $DCV_Describe_Session."creation-time"',
                        '$output["DCVLastDisconnectTime"] = $DCV_Describe_Session."last-disconnection-time"',
                        "$output | ConvertTo-Json",
                    ]

                    try:
                        check_dcv_session = client_ssm.send_command(
                            InstanceIds=[_instance_id],
                            DocumentName="AWS-RunPowerShellScript",
                            Parameters={"commands": powershell_commands},
                            TimeoutSeconds=30,
                        )
                    except ClientError as e:
                        logger.error(
                            f"windows_auto_stop_instance: Unable to query SSM for {instance_id} : {e}"
                        )
                        if "InvalidInstanceId" in str(e):
                            logger.error(
                                "windows_auto_stop_instance: Instance is not in Running state or SSM daemon is not running. This instance is probably still starting up ..."
                            )
                        ssm_failed = True

                    if ssm_failed is False:
                        ssm_command_id = check_dcv_session["Command"]["CommandId"]
                        while ssm_list_command_loop < 6:
                            check_command_status = client_ssm.list_commands(
                                CommandId=ssm_command_id
                            )["Commands"][0]["Status"]
                            if check_command_status != "Success":
                                _cmds = client_ssm.list_commands(
                                    CommandId=ssm_command_id
                                )["Commands"]
                                logger.info(
                                    f"windows_auto_stop_instance: SSM command ({ssm_command_id}) executed but did not succeed or failed yet. Waiting 20 seconds ... {_cmds}"
                                )
                                if check_command_status == "Failed":
                                    logger.error(
                                        f"windows_auto_stop_instance: Unable to query DCV for {instance_id} with SSM id {ssm_command_id}"
                                    )
                                    ssm_failed = True
                                    break
                                time.sleep(20)
                                ssm_list_command_loop += 1
                            else:
                                break

                    if ssm_list_command_loop >= 5:
                        _cmd_list = client_ssm.list_commands(CommandId=ssm_command_id)

                        logger.error(
                            f"windows_auto_stop_instance: Unable to determine status SSM responses after 2 minutes timeout for {ssm_command_id} : {_cmd_list}"
                        )
                        ssm_failed = True

                    if ssm_failed is False:
                        ssm_output = client_ssm.get_command_invocation(
                            CommandId=ssm_command_id, InstanceId=instance_id
                        )
                        session_info = json.loads(ssm_output["StandardOutputContent"])
                        session_current_connection = session_info[
                            "DCVCurrentConnections"
                        ]
                        if session_info["DCVLastDisconnectTime"] == "":
                            # handle case where user launched DCV but never accessed it
                            last_dcv_disconnect = parse(session_info["DCVCreationTime"])
                        else:
                            last_dcv_disconnect = parse(
                                session_info["DCVLastDisconnectTime"]
                            )
                        logger.info(session_info)
                        session_cpu_average = session_info[
                            "CPUAveragePerformanceLast10Secs"
                        ]
                        if session_cpu_average < config.Config.DCV_IDLE_CPU_THRESHOLD:
                            if session_current_connection == 0:
                                current_time = parse(
                                    datetime.now()
                                    .replace(microsecond=0)
                                    .replace(tzinfo=timezone.utc)
                                    .isoformat()
                                )
                                if (
                                    last_dcv_disconnect
                                    + timedelta(hours=stop_instance_after)
                                ) < current_time:
                                    logger.info(
                                        "windows_auto_stop_instance: {} is ready for {}. Last access time {}".format(
                                            instance_id, action, last_dcv_disconnect
                                        )
                                    )
                                    try:
                                        if action == "hibernate":
                                            client_ec2.stop_instances(
                                                InstanceIds=[instance_id],
                                                Hibernate=True,
                                                DryRun=True,
                                            )
                                        else:
                                            client_ec2.stop_instances(
                                                InstanceIds=[instance_id], DryRun=True
                                            )
                                    except ClientError as e:
                                        if (
                                            e.response["Error"].get("Code")
                                            == "DryRunOperation"
                                        ):
                                            if action == "hibernate":
                                                client_ec2.stop_instances(
                                                    InstanceIds=[instance_id],
                                                    Hibernate=True,
                                                )
                                            else:
                                                client_ec2.stop_instances(
                                                    InstanceIds=[instance_id]
                                                )

                                            logging.info(
                                                "windows_auto_stop_instance: Stopped {}".format(
                                                    instance_id
                                                )
                                            )
                                            try:
                                                check_session = (
                                                    WindowsDCVSessions.query.filter_by(
                                                        session_instance_id=instance_id,
                                                        session_state="running",
                                                        is_active=True,
                                                    ).first()
                                                )
                                                if check_session:
                                                    check_session.session_state = (
                                                        "stopped"
                                                    )
                                                    db.session.commit()
                                                    logger.info(
                                                        "windows_auto_stop_instance: DB entry updated"
                                                    )
                                                else:
                                                    logger.error(
                                                        "windows_auto_stop_instance: Instance ({}) has been stopped but could not find associated database entry".format(
                                                            instance_id
                                                        ),
                                                        "error",
                                                    )
                                            except Exception as e:
                                                logger.error(
                                                    "windows_auto_stop_instance: SQL Query error:".format(
                                                        e
                                                    ),
                                                    "error",
                                                )
                                        else:
                                            logger.error(
                                                "windows_auto_stop_instance: Unable to {} instance ({}) due to {}".format(
                                                    action, instance_id, e
                                                ),
                                                "error",
                                            )
                                else:
                                    logger.info(
                                        "windows_auto_stop_instance: {} NOT ready for {}. Last access time {}".format(
                                            instance_id, action, last_dcv_disconnect
                                        )
                                    )
                            else:
                                logger.info(
                                    "windows_auto_stop_instance: {} currently has active DCV sessions".format(
                                        instance_id
                                    )
                                )
                        else:
                            logger.info(
                                "windows_auto_stop_instance: CPU usage {} is above threshold {} so this host won't be subject to {}.".format(
                                    session_cpu_average,
                                    config.Config.DCV_IDLE_CPU_THRESHOLD,
                                    action,
                                )
                            )
                    else:
                        logger.error(
                            "windows_auto_stop_instance: SSM failed for {} with ssm_id {}".format(
                                instance_id, ssm_command_id
                            )
                        )


def linux_auto_stop_instance(instances_to_check):
    # Automatically stop or hibernate (when possible) instances based on Idle time and CPU usage
    with db.app.app_context():
        logger.info(f"Scheduled Task: linux_auto_stop_instance {instances_to_check}")
        get_host_to_stop = retrieve_host(instances_to_check, "running")

        logger.info(
            f"linux_auto_stop_instance: List of Linux DCV hosts subject to stop/hibernate {get_host_to_stop}"
        )

        for instance_id, instance_data in get_host_to_stop.items():
            if instance_data["hibernate_enabled"] is True:
                action = "hibernate"
                stop_instance_after = config.Config.DCV_LINUX_HIBERNATE_IDLE_SESSION
            else:
                action = "stop"
                stop_instance_after = config.Config.DCV_LINUX_STOP_IDLE_SESSION

            logger.info(
                "linux_auto_stop_instance: Trying to {} instance {} if idle for more than {} hours and  CPU % is below {}".format(
                    action,
                    instance_id,
                    stop_instance_after,
                    config.Config.DCV_IDLE_CPU_THRESHOLD,
                )
            )
            if stop_instance_after > 0:
                for instance_id in get_host_to_stop.keys():
                    logger.info("Checking Instance ID: {}".format(instance_id))
                    ssm_failed = False
                    ssm_list_command_loop = 0
                    shell_commands = [
                        "DCV_Describe_Session=$(dcv describe-session "
                        + str(instance_data["session_uuid"])
                        + " -j)",
                        "CPUAveragePerformanceLast10Secs=$(top -d 5 -b -n2 | grep 'Cpu(s)' |tail -n 1 | awk '{print $2 + $4}')",
                        "echo '{\"DCV\": '"
                        "$DCV_Describe_Session"
                        "' , \"CPUAveragePerformanceLast10Secs\": '"
                        "$CPUAveragePerformanceLast10Secs"
                        "'}'",
                    ]

                    try:
                        check_dcv_session = client_ssm.send_command(
                            InstanceIds=[instance_id],
                            DocumentName="AWS-RunShellScript",
                            Parameters={"commands": shell_commands},
                            TimeoutSeconds=30,
                        )
                    except ClientError as e:
                        logger.error(f"Unable to query SSM for {instance_id} : {e}")
                        if "InvalidInstanceId" in str(e):
                            logger.error(
                                "linux_auto_stop_instance: Instance is not in Running state or SSM daemon is not running. This instance is probably still starting up ..."
                            )
                        ssm_failed = True

                    if ssm_failed is False:
                        ssm_command_id = check_dcv_session["Command"]["CommandId"]
                        while ssm_list_command_loop < 6:
                            check_command_status = client_ssm.list_commands(
                                CommandId=ssm_command_id
                            )["Commands"][0]["Status"]
                            if check_command_status != "Success":
                                logger.info(
                                    "linux_auto_stop_instance: SSM command ({}) executed but did not succeed or failed yet. Waiting 20 seconds ... {} ".format(
                                        ssm_command_id,
                                        client_ssm.list_commands(
                                            CommandId=ssm_command_id
                                        )["Commands"],
                                    )
                                )
                                if check_command_status == "Failed":
                                    logger.error(
                                        "linux_auto_stop_instance: Unable to query DCV for {} with SSM id ".format(
                                            instance_id, ssm_command_id
                                        )
                                    )
                                    ssm_failed = True
                                    break
                                time.sleep(20)
                                ssm_list_command_loop += 1
                            else:
                                break

                    if ssm_list_command_loop >= 5:
                        logger.error(
                            "linux_auto_stop_instance: Unable to determine status SSM responses after 2 minutes timeout for {} : {} ".format(
                                ssm_command_id,
                                str(client_ssm.list_commands(CommandId=ssm_command_id)),
                            )
                        )
                        ssm_failed = True

                    if ssm_failed is False:
                        ssm_output = client_ssm.get_command_invocation(
                            CommandId=ssm_command_id, InstanceId=instance_id
                        )
                        session_info = json.loads(ssm_output["StandardOutputContent"])
                        session_current_connection = session_info["DCV"][
                            "num-of-connections"
                        ]
                        if session_info["DCV"]["last-disconnection-time"] == "":
                            # handle case where user launched DCV but never accessed it
                            last_dcv_disconnect = parse(
                                session_info["DCV"]["creation-time"]
                            )
                        else:
                            last_dcv_disconnect = parse(
                                session_info["DCV"]["last-disconnection-time"]
                            )

                        logger.info(session_info)
                        session_cpu_average = session_info[
                            "CPUAveragePerformanceLast10Secs"
                        ]
                        if session_cpu_average < config.Config.DCV_IDLE_CPU_THRESHOLD:
                            if session_current_connection == 0:
                                current_time = parse(
                                    datetime.now()
                                    .replace(microsecond=0)
                                    .replace(tzinfo=timezone.utc)
                                    .isoformat()
                                )
                                if (
                                    last_dcv_disconnect
                                    + timedelta(hours=stop_instance_after)
                                ) < current_time:
                                    logger.info(
                                        "linux_auto_stop_instance: {} is ready for {}. Last access time {}".format(
                                            instance_id, action, last_dcv_disconnect
                                        )
                                    )
                                    try:
                                        if action == "hibernate":
                                            client_ec2.stop_instances(
                                                InstanceIds=[instance_id],
                                                Hibernate=True,
                                                DryRun=True,
                                            )
                                        else:
                                            client_ec2.stop_instances(
                                                InstanceIds=[instance_id], DryRun=True
                                            )
                                    except ClientError as e:
                                        if (
                                            e.response["Error"].get("Code")
                                            == "DryRunOperation"
                                        ):
                                            if action == "hibernate":
                                                client_ec2.stop_instances(
                                                    InstanceIds=[instance_id],
                                                    Hibernate=True,
                                                )
                                            else:
                                                client_ec2.stop_instances(
                                                    InstanceIds=[instance_id]
                                                )

                                            logging.info(
                                                "linux_auto_stop_instance: Stopped {}".format(
                                                    instance_id
                                                )
                                            )
                                            try:
                                                check_session = (
                                                    LinuxDCVSessions.query.filter_by(
                                                        session_instance_id=instance_id,
                                                        session_state="running",
                                                        is_active=True,
                                                    ).first()
                                                )
                                                if check_session:
                                                    check_session.session_state = (
                                                        "stopped"
                                                    )
                                                    db.session.commit()
                                                    logger.info(
                                                        "linux_auto_stop_instance: DB entry updated"
                                                    )
                                                else:
                                                    logger.error(
                                                        "linux_auto_stop_instance: Instance ({}) has been stopped but could not find associated database entry".format(
                                                            instance_id
                                                        ),
                                                        "error",
                                                    )
                                            except Exception as e:
                                                logger.error(
                                                    "linux_auto_stop_instance: SQL Query error:".format(
                                                        e
                                                    ),
                                                    "error",
                                                )
                                        else:
                                            logger.error(
                                                "linux_auto_stop_instance: Unable to {} instance ({}) due to {}".format(
                                                    action, instance_id, e
                                                ),
                                                "error",
                                            )
                                else:
                                    logger.info(
                                        "linux_auto_stop_instance: {} NOT ready for {}. Last access time {}".format(
                                            instance_id, action, last_dcv_disconnect
                                        )
                                    )
                            else:
                                logger.info(
                                    "linux_auto_stop_instance: {} currently has active DCV sessions".format(
                                        instance_id
                                    )
                                )
                        else:
                            logger.info(
                                "linux_auto_stop_instance: CPU usage {} is above threshold {} so this host won't be subject to {}.".format(
                                    session_cpu_average,
                                    config.Config.DCV_IDLE_CPU_THRESHOLD,
                                    action,
                                )
                            )
                    else:
                        logger.error(
                            "linux_auto_stop_instance: SSM failed for {} with ssm_id {}".format(
                                instance_id, ssm_command_id
                            )
                        )


def auto_terminate_stopped_instance():
    with db.app.app_context():
        for distribution in ["linux", "windows"]:
            logger.info(
                "Scheduled Task: auto_terminate_stopped_instance {} ".format(
                    distribution
                )
            )
            try:
                if distribution == "windows":
                    terminate_stopped_instance_after = int(
                        config.Config.DCV_WINDOWS_TERMINATE_STOPPED_SESSION
                    )
                else:
                    terminate_stopped_instance_after = int(
                        config.Config.DCV_LINUX_TERMINATE_STOPPED_SESSION
                    )
            except Exception as err:
                logger.error(
                    f"auto_terminate_stopped_instance: {terminate_stopped_instance_after} is not a valid integer. Script will not proceed to auto-termination. Error: {err}"
                )
                terminate_stopped_instance_after = 0

            logger.info(
                f"auto_terminate_stopped_instance: terminate_stopped_instance_after for {distribution} set to {terminate_stopped_instance_after}"
            )
            if terminate_stopped_instance_after > 0:
                get_host_to_terminate = retrieve_host({}, "stopped")
                logger.info(
                    f"auto_terminate_stopped_instance: List of hosts that are subject to termination if stopped for more than {terminate_stopped_instance_after} hours for {distribution}: {get_host_to_terminate}"
                )
                for instance_id, session_info in get_host_to_terminate.items():
                    if (
                        session_info["stopped_time"]
                        + timedelta(hours=terminate_stopped_instance_after)
                    ) < session_info["current_time"]:
                        logger.info(
                            "auto_terminate_stopped_instance: Instance {} is ready to be terminated".format(
                                session_info["stack_name"]
                            )
                        )
                        try:
                            # change with cloudformation terminate
                            client_cloudformation.delete_stack(
                                StackName=session_info["stack_name"]
                            )
                            try:
                                if distribution == "windows":
                                    check_session = WindowsDCVSessions.query.filter_by(
                                        session_instance_id=instance_id, is_active=True
                                    ).first()
                                else:
                                    check_session = LinuxDCVSessions.query.filter_by(
                                        session_instance_id=instance_id, is_active=True
                                    ).first()
                                if check_session:
                                    check_session.is_active = False
                                    check_session.deactivated_in = datetime.now(
                                        timezone.utc
                                    )
                                    db.session.commit()
                                    logger.info(
                                        f"auto_terminate_stopped_instance: {instance_id} has been terminated and set to inactive on the database."
                                    )
                                else:
                                    logger.error(
                                        f"auto_terminate_stopped_instance: Instance ({instance_id}) has been stopped but could not find associated database entry"
                                    )
                            except Exception as e:
                                logger.error(
                                    "auto_terminate_stopped_instance: SQL Query error:".format(
                                        e
                                    ),
                                    "error",
                                )
                        except ClientError as e:
                            logger.info(
                                f"auto_terminate_stopped_instance: Unable to delete instance due to {e}"
                            )
                    else:
                        logger.error(
                            f"auto_terminate_stopped_instance: Unable to delete associated instance ({instance_id}) due to {e}"
                        )
            else:
                logger.info(
                    f"auto_terminate_stopped_instance: Auto-terminate stopped instances is not enabled for {distribution}"
                )


def schedule_auto_start():
    days_human_format = {
        1: "monday",
        2: "tuesday",
        3: "wednesday",
        4: "thursday",
        5: "friday",
        6: "saturday",
        7: "sunday",
    }
    current_time = now()
    current_hour = current_time.hour
    current_minute = current_time.minute
    current_day = days_human_format[current_time.isoweekday()]
    format_hour = (current_hour * 60) + current_minute
    for distribution in ["windows", "linux"]:
        logger.info(f"Scheduled Task: schedule_auto_start {distribution}")
        column_start_hour = "schedule_" + current_day + "_start"
        column_stop_hour = "schedule_" + current_day + "_stop"
        if distribution == "windows":
            all_sessions = WindowsDCVSessions.query.filter(
                getattr(WindowsDCVSessions, column_start_hour) < format_hour,
                format_hour < getattr(WindowsDCVSessions, column_stop_hour),
                getattr(WindowsDCVSessions, "is_active") == 1,
                getattr(WindowsDCVSessions, "session_state") == "stopped",
            ).all()
        else:
            all_sessions = LinuxDCVSessions.query.filter(
                getattr(LinuxDCVSessions, column_start_hour) < format_hour,
                format_hour < getattr(LinuxDCVSessions, column_stop_hour),
                getattr(LinuxDCVSessions, "is_active") == 1,
                getattr(LinuxDCVSessions, "session_state") == "stopped",
            ).all()

        logger.info(f"All sessions: {all_sessions}")
        logger.info(
            f"schedule_auto_start: Checking if any instance is stopped but must be running on {current_day} after {format_hour}"
        )
        for session in all_sessions:
            logger.info(f"schedule_auto_start: Detected {session}")
            instance_id = session.session_instance_id
            try:
                client_ec2.start_instances(InstanceIds=[instance_id], DryRun=True)
            except ClientError as e:
                if e.response["Error"].get("Code") == "DryRunOperation":
                    try:
                        client_ec2.start_instances(InstanceIds=[instance_id])
                        session.session_state = "pending"
                        db.session.commit()
                        logger.info(f"Started {instance_id}")
                    except Exception as err:
                        logger.error(
                            f"schedule_auto_start: Unable to restart instance ({instance_id}) due to {err}"
                        )
                else:
                    logger.error(
                        f"schedule_auto_start: Unable to restart instance ({instance_id}) due to {e}"
                    )


def schedule_auto_stop():
    days_human_format = {
        1: "monday",
        2: "tuesday",
        3: "wednesday",
        4: "thursday",
        5: "friday",
        6: "saturday",
        7: "sunday",
    }
    current_time = now()
    current_hour = current_time.hour
    current_minute = current_time.minute
    current_day = days_human_format[current_time.isoweekday()]
    format_hour = (current_hour * 60) + current_minute

    for distribution in ["windows", "linux"]:
        instances_ids_to_check = {}
        logger.info(
            f"Scheduled Task: schedule_auto_stop for Distribution {distribution}"
        )
        column_start_hour = "schedule_" + current_day + "_start"
        column_stop_hour = "schedule_" + current_day + "_stop"

        for query in ["norun", "schedule"]:
            logger.debug(f"Running query type of: {query}")

            if query == "schedule":
                # schedule: check if current time is outside run time
                if distribution == "windows":
                    all_sessions = WindowsDCVSessions.query.filter(
                        or_(
                            getattr(WindowsDCVSessions, column_start_hour)
                            > format_hour,
                            format_hour > getattr(WindowsDCVSessions, column_stop_hour),
                        ),
                        getattr(WindowsDCVSessions, "is_active") == 1,
                        getattr(WindowsDCVSessions, "session_state") == "running",
                    ).all()
                else:
                    all_sessions = LinuxDCVSessions.query.filter(
                        or_(
                            getattr(LinuxDCVSessions, column_start_hour) > format_hour,
                            format_hour > getattr(LinuxDCVSessions, column_stop_hour),
                        ),
                        getattr(LinuxDCVSessions, "is_active") == 1,
                        getattr(LinuxDCVSessions, "session_state") == "running",
                    ).all()
            else:
                # norun, instance stopped all day when start_hour and stop_hour = 0
                if distribution == "windows":
                    all_sessions = WindowsDCVSessions.query.filter(
                        getattr(WindowsDCVSessions, column_start_hour) == 0,
                        getattr(WindowsDCVSessions, column_stop_hour) == 0,
                        getattr(WindowsDCVSessions, "is_active") == 1,
                        getattr(WindowsDCVSessions, "session_state") == "running",
                    ).all()
                else:
                    all_sessions = LinuxDCVSessions.query.filter(
                        getattr(LinuxDCVSessions, column_start_hour) == 0,
                        getattr(LinuxDCVSessions, column_stop_hour) == 0,
                        getattr(LinuxDCVSessions, "is_active") == 1,
                        getattr(LinuxDCVSessions, "session_state") == "running",
                    ).all()

            logger.debug(
                f"schedule_auto_stop: Found {len(all_sessions)} sessions: {all_sessions}"
            )

            logger.info(
                f"schedule_auto_stop: Checking if any instance is running but must be stopped on {current_day} after {format_hour}"
            )
            for session in all_sessions:
                logger.info(f"schedule_auto_stop: Detected session {session}")
                if distribution == "windows":
                    instances_ids_to_check[session.session_instance_id] = "windows"
                else:
                    instances_ids_to_check[
                        session.session_instance_id
                    ] = session.session_linux_distribution

        if distribution == "windows":
            windows_auto_stop_instance(
                dict(
                    (instance_id, instance_distro)
                    for instance_id, instance_distro in instances_ids_to_check.items()
                    if instance_distro == "windows"
                )
            )
        else:
            linux_auto_stop_instance(
                dict(
                    (instance_id, instance_distro)
                    for instance_id, instance_distro in instances_ids_to_check.items()
                    if instance_distro != "windows"
                )
            )
        