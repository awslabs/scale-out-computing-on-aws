# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from models import db, VirtualDesktopSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ssm_parameter_store import SocaConfig
from utils.http_client import SocaHttpClient
from utils.response import SocaResponse
from botocore.exceptions import ClientError
import config
from cryptography.fernet import Fernet
import json
from sqlalchemy.orm import Session
import base64
from typing import Dict, Iterator, List, Union, Literal, Iterable, TypeVar
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from itertools import islice
import time

logger = logging.getLogger("scheduled_tasks_virtual_desktops_session_state_watcher")

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message
client_ssm = utils_boto3.get_boto(service_name="ssm").message


def chunked_iterable(iterable: Iterable[TypeVar], chunk_size: int) -> Iterator[List]:
    iterator = iter(iterable)
    for first in iterator:
        yield [first] + list(islice(iterator, chunk_size - 1))


def process_chunk(
    sessions: list[VirtualDesktopSessions],
    instance_ids_by_state: dict,
) -> SocaResponse:
    _db_scoped_session = db.session
    """
    This function is responsible to retrieve all active VDI desktops and ensure the status displayed on the Web Interface match the state of the process running on the EC2 machine
    """
    try:
        logger.info(f"Processing chunk {sessions}")

        _get_soca_parameters = SocaConfig(key="/").get_value(return_as=dict)
        if _get_soca_parameters.get("success") is False:
            logger.critical(
                f"Unable to retrieve SOCA Parameters: {_get_soca_parameters.get('message')}"
            )
            return SocaResponse(
                success=False,
                message=f"Unable to retrieve SOCA Parameters: {_get_soca_parameters.get('message')}",
            )
        else:
            _soca_parameters = _get_soca_parameters.get("message")

        logger.info("Finding VDI sessions with no registered EC2 Instance on DB ...")
        _sessions_with_no_ec2_instance = [
            session
            for session in sessions
            if session.instance_private_dns is None
            or session.instance_private_ip is None
            or session.instance_id is None
        ]
        if _sessions_with_no_ec2_instance:
            logger.info(
                f"Found Sessions with no EC2 Instance: {_sessions_with_no_ec2_instance}"
            )
            update_ec2_info(
                sessions=_sessions_with_no_ec2_instance,
                cluster_id=_soca_parameters.get("/configuration/ClusterId"),
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("All VDI sessions have active EC2 instance on DB")

        logger.info(
            "Finding VDI sessions with invalid or terminated Instance ID. Deleting associated CloudFormation stack if needed ..."
        )
        _inactive_sessions = [
            session
            for session in sessions
            if instance_ids_by_state.get(session.instance_id) in [None, "terminated"]
        ]

        if _inactive_sessions:
            logger.info(
                f"Found Sessions that can be deactivated {_inactive_sessions} depending on the CloudFormation stack status"
            )
            delete_inactive_instances(
                sessions=_inactive_sessions,
                instance_ids_state=instance_ids_by_state,
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No inactive session found")

        # Update stopped sessions
        logger.info(
            "Finding VDI Sessions with stopped EC2 Instance but DB state is not stopped (e.g: if you stop the instance from AWS Console)"
        )

        _sync_stopped_sessions = [
            session
            for session in sessions
            if session.instance_id is not None
            and instance_ids_by_state.get(session.instance_id) is not None
            and instance_ids_by_state.get(session.instance_id).lower()
            in ["stopped", "stopping"]
            and session.session_state.lower() != "stopped"
        ]
        logger.info(
            f"Found stopped EC2 instances not in sync with DB session_state {_sync_stopped_sessions}"
        )
        if _sync_stopped_sessions:
            logger.info(
                f"Found Sessions to update state to stopped: {_sync_stopped_sessions}"
            )
            update_virtual_desktop_state(
                sessions=_sync_stopped_sessions,
                new_state="stopped",
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No session to update to stopped")

        # Retrieve all non-running VDI session with a running Instance ID.
        logger.info(
            "Finding non-running VDI Sessions but associated EC2 instance is running, check if DCV is up and running and change the state to running"
        )

        _sync_running_sessions = [
            session
            for session in sessions
            if session.instance_id is not None
            and instance_ids_by_state.get(session.instance_id) is not None
            and instance_ids_by_state[session.instance_id].lower() == "running"
            and session.session_state.lower() != "running"
        ]

        _running_sessions_to_validate = []
        if _sync_running_sessions:
            logger.info(
                f"Found running EC2 instances but session_state are not running {_sync_running_sessions}, checking if DCV is healthy on these machine"
            )
            for _session in _sync_running_sessions:
                _dcv_https_url = f"https://{_soca_parameters.get('/configuration/DCVEntryPointDNSName')}/{_session.instance_private_dns}/"
                _check_dcv_state = SocaHttpClient(
                    endpoint=_dcv_https_url, allow_redirects=False, timeout=5
                ).get()
                logger.debug(
                    f"LoadBalancer Result {_dcv_https_url} -> {_check_dcv_state}"
                )
                # We change status to 200 only if DCVEntryPointDNSName returns 200 and if we can get `dcv` as part of  returned headers
                if _check_dcv_state.get("status_code") == 200:
                    _response_headers = _check_dcv_state.get("request").headers
                    logger.debug(
                        f"Headers response for {_session.id=} {_session.session_uuid=}: {_response_headers}"
                    )
                    if "Server" in _response_headers:
                        if _response_headers.get("Server") == "dcv":
                            # We will also validate if DCV is responding correctly before changing the status to running
                            _running_sessions_to_validate.append(_session)
                else:
                    update_virtual_desktop_state(
                        sessions=[_session],
                        new_state="pending",
                        db_scoped_session=_db_scoped_session,
                    )
        else:
            logger.info("No VDI sessions to be changed to running")

        if _running_sessions_to_validate:
            logger.info(
                f"Found EC2 running and DCV listening for {_running_sessions_to_validate}, will verify if dcv describe-session is correct and update status to running"
            )
            validate_dcv_session(
                sessions=_running_sessions_to_validate,
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No session to update to running")

        # Update pending sessions
        logger.info(
            "Finding VDI Session with running EC2 instance type but stopped state. updating them to pending"
        )
        _sync_pending_sessions = [
            session
            for session in sessions
            if session.instance_id is not None
            and instance_ids_by_state.get(session.instance_id) is not None
            and instance_ids_by_state.get(session.instance_id).lower() == "running"
            and session.session_state.lower() == "stopped"
        ]
        if _sync_pending_sessions:
            logger.info(f"Found sessions to update to pending {_sync_pending_sessions}")
            update_virtual_desktop_state(
                sessions=_sync_pending_sessions,
                new_state="pending",
                db_scoped_session=_db_scoped_session,
            )
        else:
            logger.info("No session to update to pending")

    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(f"Process Chunk error due to {err} at line {exc_tb.tb_lineno}")

    # Close current thread
    return SocaResponse(success=True, message="Chunk processed")


def ssm_get_command_info(os_family: Literal["linux", "windows"]) -> SocaResponse:
    """
    Returns the SSM command & document name to run based on the operating system

    Run dcv describe-session command
    - Return 0 is the command exists
    -  Return 1 for any error
    """

    if os_family not in ["linux", "windows"]:
        logger.critical(f"os_family must be linux or windows, detected {os_family}")

    if os_family == "windows":
        _ssm_commands = [
            f"Invoke-Expression \"& 'C:\\Program Files\\NICE\\DCV\\Server\\bin\\dcv' describe-session $env:SOCA_DCV_SESSION_ID\"",
            "if ($?) { exit 0 }",
            "Restart-Service -Name dcvserver -Force",
            "Start-Sleep -Seconds 5",
            f"Invoke-Expression \"& 'C:\\Program Files\\NICE\\DCV\\Server\\bin\\dcv' describe-session $env:SOCA_DCV_SESSION_ID\"",
            "if ($?) { exit 0 } else { exit 1 }",
        ]

        _ssm_document_name = "AWS-RunPowerShellScript"

    else:
        _ssm_commands = [
            "export SOCA_DCV_SESSION_ID=$(cat /etc/environment | grep SOCA_DCV_SESSION_ID= | awk -F'=' '{print $2}')",  # ssm.send_command() cannot use source",
            f"if dcv describe-session $SOCA_DCV_SESSION_ID; then",
            " exit 0",
            "fi",
            " ",
            "systemctl restart socadcv;",
            "sleep 5",
            "",
            f"if dcv describe-session $SOCA_DCV_SESSION_ID; then",
            "exit 0",
            "else",
            "exit 1 ",
            "fi",
        ]
        _ssm_document_name = "AWS-RunShellScript"

    return SocaResponse(
        success=True,
        message={
            "ssm_commands": _ssm_commands,
            "ssm_document_name": _ssm_document_name,
        },
    )


def ssm_get_list_command_status(command_id: str) -> SocaResponse:
    """
    Returns the status of the SSM command ID.
    Valid status are either Success or Failed (this means the SSM command has completed successfully)

    """
    try:
        _max_ssm_loop_attempts = 10
        _ssm_attempt = 1
        while True:
            _check_command_status = client_ssm.list_commands(CommandId=command_id)[
                "Commands"
            ][0]["Status"]
            logger.info(f"Status command for {command_id}: {_check_command_status}")
            if _check_command_status in ["Success", "Failed"]:
                return SocaResponse(
                    success=True,
                    message=f"Command {command_id} has completed, checking each instance results",
                )
            else:
                if _check_command_status in ["InProgress", "Pending"]:
                    if _ssm_attempt == _max_ssm_loop_attempts:
                        logger.critical(
                            f"Unable to determine status SSM responses after timeout for {command_id}"
                        )
                        return SocaResponse(
                            success=False,
                            message=f"Unable to determine status SSM responses after timeout for {command_id}",
                        )
                    else:
                        time.sleep(5)
                        _ssm_attempt += 1
                else:
                    logger.critical(
                        f"SSM command {command_id} exited with invalid status {_check_command_status=}"
                    )
                    return SocaResponse(
                        success=False,
                        message=f"SSM command {command_id} exited with invalid status {_check_command_status=}",
                    )
    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(
            f"ssm_get_list_command_status error due to {err} at line {exc_tb.tb_lineno}"
        )


def validate_dcv_session(
    sessions: VirtualDesktopSessions, db_scoped_session: Session
) -> SocaResponse:
    """
    ssm.send_command takes up to 50 InstanceIDs. Make sure the maximum chunk size is not greater than 50
    """
    try:
        _linux_sessions_instance_ids = [
            session.instance_id for session in sessions if session.os_family == "linux"
        ]

        logger.info(
            f"Found Linux Sessions to validate DCV: {_linux_sessions_instance_ids}"
        )
        _windows_sessions_instance_ids = [
            session.instance_id
            for session in sessions
            if session.os_family == "windows"
        ]
        logger.info(
            f"Found Windows Sessions to validate DCV: {_windows_sessions_instance_ids}"
        )
        _linux_ssm_info = ssm_get_command_info(os_family="linux")
        if _linux_ssm_info.get("success") is False:
            logger.critical(
                f"Unable to retrieve SSM command info for linux due to {_linux_ssm_info.get('message')}"
            )
            return SocaResponse(success=False, message=_linux_ssm_info.get("message"))
        _windows_ssm_info = ssm_get_command_info(os_family="windows")

        if _windows_ssm_info.get("success") is False:
            logger.critical(
                f"Unable to retrieve SSM command info for Windows due to {_windows_ssm_info.get('message')}"
            )
            return SocaResponse(success=False, message=_windows_ssm_info.get("message"))

        # Run SSM for Linux and Windows hosts
        if _linux_sessions_instance_ids:
            _check_dcv_session_linux = client_ssm.send_command(
                InstanceIds=_linux_sessions_instance_ids,
                DocumentName=_linux_ssm_info.get("message").get("ssm_document_name"),
                Parameters={
                    "commands": _linux_ssm_info.get("message").get("ssm_commands")
                },
                TimeoutSeconds=30,
            )
            _ssm_command_id_linux = _check_dcv_session_linux["Command"]["CommandId"]

        else:
            logger.info("No Linux instances to check")
            _ssm_command_id_linux = False

        if _windows_sessions_instance_ids:
            _check_dcv_session_windows = client_ssm.send_command(
                InstanceIds=_windows_sessions_instance_ids,
                DocumentName=_windows_ssm_info.get("message").get("ssm_document_name"),
                Parameters={
                    "commands": _windows_ssm_info.get("message").get("ssm_commands")
                },
                TimeoutSeconds=30,
            )
            _ssm_command_id_windows = _check_dcv_session_windows["Command"]["CommandId"]

        else:
            logger.info("No Windows instances to check")
            _ssm_command_id_windows = False

        # Wait until the Commands have completed.
        # Succeed => All instances succeeded
        # Failed => At least 1 instance failed, but other may have succeeded
        # All others return code => SSM command was not executed for various reason (Quota, Rate Exceeded etc ..)

        _skip_linux = False
        _skip_windows = False

        if _ssm_command_id_linux is False:
            _skip_linux = True
        else:
            _check_linux_command_status = ssm_get_list_command_status(
                command_id=_ssm_command_id_linux
            )
            if _check_linux_command_status.get("success") is False:
                logger.error(
                    f"Unable to determine status SSM responses for linux instances due to {_check_linux_command_status}"
                )
                _skip_linux = True

        if _ssm_command_id_windows is False:
            _skip_windows = True
        else:
            _check_windows_command_status = ssm_get_list_command_status(
                command_id=_ssm_command_id_windows
            )
            if _check_windows_command_status.get("success") is False:
                logger.error(
                    f"Unable to determine status SSM responses for windows instances due to {_check_windows_command_status}"
                )
                _skip_windows = True

        # Check all linux hosts individually
        if _skip_linux is False:
            for _session in [
                session for session in sessions if session.os_family == "linux"
            ]:
                _ssm_output = client_ssm.get_command_invocation(
                    CommandId=_ssm_command_id_linux, InstanceId=_session.instance_id
                )
                _status = _ssm_output.get("Status")
                logger.info(f"Validating {_session}, received ssm output {_status}")
                if _status.lower() != "success":
                    logger.warning(
                        f"DCV Session not running properly on {_session.instance_id} for DCV Session {_session.session_uuid}, this may be because system has just started. DCV Error state will be checked by session_error_watcher.py"
                    )

                else:
                    logger.info(
                        f"DCV Session running properly on {_session.instance_id} for DCV Session {_session.session_uuid}, changing state to running"
                    )
                    update_virtual_desktop_state(
                        sessions=[_session],
                        new_state="running",
                        db_scoped_session=db_scoped_session,
                    )
        # Check all Windows hosts individually
        if _skip_windows is False:
            for _session in [
                session for session in sessions if session.os_family == "windows"
            ]:
                _ssm_output = client_ssm.get_command_invocation(
                    CommandId=_ssm_command_id_windows, InstanceId=_session.instance_id
                )
                _status = _ssm_output.get("Status")
                logger.info(f"Validating {_session}, received ssm output {_status}")
                if _status.lower() != "success":
                    logger.warning(
                        f"DCV Session not running properly on {_session.instance_id} for DCV Session {_session.session_uuid}, this may be because system has just started. DCV Error state will be checked by session_error_watcher.py"
                    )

                else:
                    logger.info(
                        f"DCV Session running properly on {_session.instance_id} for DCV Session {_session.session_uuid}, changing state to running"
                    )
                    update_virtual_desktop_state(
                        sessions=[_session],
                        new_state="running",
                        db_scoped_session=db_scoped_session,
                    )
    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(
            f"validate_dcv_session error due to {err} at line {exc_tb.tb_lineno}"
        )
        return SocaResponse(success=False, message=err)

    return SocaResponse(success=True, message="DCV Session validated successfully")


def encrypt(message: base64) -> SocaResponse:
    """
    This function create the DCV Authentication Code
    """
    try:
        key = config.Config.DCV_TOKEN_SYMMETRIC_KEY
        cipher_suite = Fernet(key)
        return SocaResponse(
            success=True, message=cipher_suite.encrypt(message.encode("utf-8"))
        )
    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(f"encrypt error due to {err} at line {exc_tb.tb_lineno}")
        return SocaResponse(success=False, message=err)


def update_ec2_info(
    sessions: VirtualDesktopSessions, cluster_id: str, db_scoped_session: Session
) -> None:
    """
    Find details for VDI session with no active EC2 Instance registered on the database (e.g: desktop that just launched).
    If EC2 capacity is provisioned, retrieve private IP/DNS, generate authentication token and update DB
    If EC2 capacity is not yet provisioned, we verify if the CloudFormation stack associated to the vdi session is in progress.
    """

    for _session in sessions:
        try:
            _session_uuid = _session.session_uuid
            _base_os = _session.instance_base_os
            _owner = _session.session_owner
            logger.info(
                f"Checking get_ec2_host_info for VDI Session {_session.id} with tag:soca:DCVSessionUUID: {_session_uuid}, tag:soca:ClusterId {cluster_id}, tag:soca:JobOwner {_owner} and tag:soca:DCVSystem {_base_os}"
            )
            _host_info = {}

            _find_instance = client_ec2.describe_instances(
                Filters=[
                    {
                        "Name": "tag:soca:DCVSessionUUID",
                        "Values": [_session.session_uuid],
                    },
                    {"Name": "tag:soca:ClusterId", "Values": [cluster_id]},
                    {"Name": "tag:soca:DCVSystem", "Values": [_base_os]},
                    {"Name": "tag:soca:JobOwner", "Values": [_owner]},
                ],
            )

            if not _find_instance["Reservations"]:
                logger.warning(
                    f"No instance found for tag:soca:DCVSessionUUID: {_session_uuid}, checking if the associated CloudFormation stack is healthy"
                )
            else:
                logger.debug(f"Found Instance: {_find_instance}")
                for reservation in _find_instance["Reservations"]:
                    for instance in reservation["Instances"]:
                        if instance["PrivateDnsName"].split(".")[0]:
                            _host_private_dns = instance["PrivateDnsName"].split(".")[
                                0
                            ]  # ip-192-168-1-10.ec2.internal -> we only get the first part
                            _host_private_ip_address = instance["PrivateIpAddress"]
                            _host_instance_id = instance["InstanceId"]
                            _host_status = instance["State"]["Name"]

                            logger.info(
                                f"EC2 instance found for {_session.id=} {_session.session_uuid=}, creating authentication token"
                            )
                            _authentication_data = json.dumps(
                                {
                                    "system": _session.instance_base_os,
                                    "instance_id": _host_instance_id,
                                    "session_token": _session.session_token,
                                    "session_user": _session.session_owner,
                                }
                            )

                            try:
                                if (
                                    generate_auth_token := encrypt(
                                        message=_authentication_data
                                    )
                                ).get("success") is False:
                                    logger.error(
                                        f"Unable to generate authentication token because of {generate_auth_token.get('message')}"
                                    )
                                    continue
                                else:
                                    session_authentication_token = base64.b64encode(
                                        generate_auth_token.get("message")
                                    ).decode("utf-8")
                                    _session.authentication_token = (
                                        session_authentication_token
                                    )

                            except Exception as err:
                                logger.error(
                                    f"Unable to update dcv auth token for {_session.id=} {_session.session_uuid=} in DB due to {err}"
                                )
                                continue

                            try:
                                logger.info(
                                    f"New EC2 instance detected for {_session.id=} {_session.session_uuid=}, adding {_host_instance_id=}, {_host_private_dns=}, {_host_private_ip_address=} to DB"
                                )
                                _session.instance_id = _host_instance_id
                                _session.instance_private_ip = _host_private_ip_address
                                _session.instance_private_dns = _host_private_dns
                                try:
                                    db_scoped_session.commit()
                                    logger.info("Changes commited successfully")
                                except Exception as e:
                                    db_scoped_session.rollback()
                                    logger.critical(
                                        f"Error trying to run the following commits on update_virtual_desktop_state because of: {e}"
                                    )
                                    queries = [
                                        str(statement)
                                        for statement in db_scoped_session._logger.handlers[
                                            0
                                        ].baseFilename
                                    ]
                                    logger.critical(f"Failed SQL query: {queries}")

                            except Exception as err:
                                logger.error(
                                    f"Unable to update host info for {_session.id=} {_session.session_uuid=} because of {err}"
                                )
                                continue
                        else:
                            logger.info(
                                "No Host information for session, will try again in the next run"
                            )
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.critical(
                f"update_ec2_info error due to {err} at line {exc_tb.tb_lineno}"
            )
            return SocaResponse(success=False, message=err)


def find_instance_ids_instance_state(
    all_sessions: VirtualDesktopSessions,
) -> SocaResponse:
    """
    Returns a dictionary of instance ID -> Instance State. Returns None if Instance ID does not exist anymore
    """
    try:
        logger.info(
            f"Finding instance state name for each instance ID for list of VDI {all_sessions}"
        )

        _instance_ids_state = {}

        # First, we get all Instance IDs, and we confirm they still exist.
        _all_instance_ids = [
            session.instance_id
            for session in all_sessions
            if session.instance_id is not None
        ]

        batch_size = 100  # max number of Instances IDs we can pass as part of describe_instance_status
        for i in range(0, len(_all_instance_ids), batch_size):
            _instance_ids_batch = _all_instance_ids[i : i + batch_size]
            logger.info(
                f"Verifying if EC2 instance still exist. Processing batch {(i // batch_size) + 1}: {_instance_ids_batch}"
            )
            try:
                response = client_ec2.describe_instance_status(
                    InstanceIds=_instance_ids_batch,
                    IncludeAllInstances=True,  # required to also display instance not in Running state
                )

                # The response contains a list of statuses
                instance_statuses = response.get("InstanceStatuses", [])
                # Iterate through the returned statuses and print details
                for status in instance_statuses:
                    _instance_ids_state[status.get("InstanceId")] = status.get(
                        "InstanceState", {}
                    ).get("Name")

                    logger.debug(
                        f"Instance {status.get('InstanceId')} is in state: {status.get('InstanceState')}"
                    )
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code in [
                    "InvalidInstanceID.NotFound",
                ]:
                    logger.warning(
                        f"Error encountered in batch. Processing each instance individually to isolate invalid IDs."
                    )
                    for _instance_id in _instance_ids_batch:
                        try:
                            individual_response = client_ec2.describe_instance_status(
                                InstanceIds=[_instance_id]
                            )
                            statuses = individual_response.get("InstanceStatuses", [])
                            if statuses:
                                for status in statuses:
                                    _instance_ids_state[_instance_id] = status.get(
                                        "InstanceState", {}
                                    ).get("Name")
                            else:
                                logger.error(
                                    f"Instance {_instance_id} returned no status (might be stopped or not yet checked)"
                                )
                        except ClientError as inner_e:
                            if inner_e.response["Error"]["Code"] in [
                                "InvalidInstanceID.NotFound"
                            ]:
                                logger.error(
                                    f"Instance ID {_instance_id} not found. Skipping..."
                                )
                                _instance_ids_state[_instance_id] = None
                            else:
                                logger.error(
                                    f"Unable to check {_instance_id}: {inner_e}"
                                )
                else:
                    logger.error(f"Unable to batch check instance state: {e}")

        return SocaResponse(success=True, message=_instance_ids_state)

    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        logger.critical(
            f"find_instance_ids_instance_state error due to {err} at line {exc_tb.tb_lineno}"
        )
        return SocaResponse(
            success=False,
            message=f"find_instance_ids_instance_state error due to {err} at line {exc_tb.tb_lineno}",
        )


def delete_inactive_instances(
    sessions: VirtualDesktopSessions,
    instance_ids_state: dict,
    db_scoped_session: Session,
):
    """

    If an session does not have any associated instance id, it means:
    1 - the session was just initiated and the CloudFormation stack has not created the EC2 capacity yet
    2 - the EC2 machine and/or CloudFormation Stack has been either removed from AWS console/CLI

    If 2), we don't try to delete the Cloudformation stack if needed and we updated the is_active flag for the session to False
    """

    logger.info(
        f"Finding inactive instances & Deleting Associated Stack for the following list: {sessions}"
    )
    for _session in sessions:
        _stack_name = _session.stack_name
        _session_uuid = _session.session_uuid
        _session_instance_id = _session.instance_id

        _stack_deleted = False
        logger.info(f"Checking CFN stack {_stack_name} for session {_session_uuid}")

        _instance_id_current_state = instance_ids_state.get(_session_instance_id)

        if _instance_id_current_state == "terminated":
            logger.info(
                f"{_session_instance_id=} is terminated, deleting stack if it exist"
            )
            try:
                client_cfn.delete_stack(StackName=_stack_name)
                logger.info(f"{_stack_name=} deleted")
                _stack_deleted = True
            except Exception as e:
                logger.error(f"Unable to delete stack {_stack_name}: {e}")
        else:
            logger.info(
                f"{_session_instance_id=} exist {_session.id=} {_session.session_uuid=}, checking CFN stack status, ensuring it's still being provisioned"
            )
            try:
                check_stack = client_cfn.describe_stacks(StackName=_stack_name)
                _stack_status = check_stack["Stacks"][0]["StackStatus"]
            except Exception as err:
                _stack_status = "STACK_UNKNOWN"  # handle case where CFN has been removed via AWS Console/APIs
                logger.error(
                    f"Error Retrieving {_stack_name=} due to {err}, deleting record from database"
                )

            logger.info(f"CloudFormation Stack {_stack_name} status: {_stack_status}")

            if _stack_status in [
                "STACK_UNKNOWN",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            ]:
                logger.info(
                    f"CloudFormation Stack associated does not exist or is being deleted, removing this session from the database"
                )
                try:
                    client_cfn.delete_stack(StackName=_stack_name)
                    logger.info(f"{_stack_name=} deleted")
                    _stack_deleted = True
                except Exception as e:
                    logger.error(f"Unable to delete {_stack_name=}: {e}")
            else:
                logger.info(
                    f"CloudFormation Stack exist and is in valid state, capacity will be provisioned soon ... "
                )

        if _stack_deleted is True:
            try:
                logger.info("Updating is_active flag to False")
                _session.is_active = False
                _session.deactivated_on = datetime.now(timezone.utc)
                _session.deactivated_by = "SCHEDULED_TASK"
                _session.session_state_latest_change_time = datetime.now(timezone.utc)
                try:
                    db_scoped_session.commit()
                    logger.info(
                        f"Session {_session.id} {_session.session_uuid=} has been deactivated successfully on the database"
                    )
                except Exception as e:
                    db_scoped_session.rollback()
                    logger.critical(
                        f"Error trying to run the following commits on update_virtual_desktop_state because of: {e}"
                    )
                    queries = [
                        str(statement)
                        for statement in db_scoped_session._logger.handlers[
                            0
                        ].baseFilename
                    ]
                    logger.critical(f"Failed SQL query: {queries}")

            except Exception as err:
                logger.error(f"Unable to update is_active flag to False: {err}")
                continue


def update_virtual_desktop_state(
    sessions: VirtualDesktopSessions, new_state: str, db_scoped_session: Session
):
    for _session in sessions:
        try:
            logger.info(
                f"Updating state for session {_session.id=} {_session.session_uuid=} to {new_state} in the database, current state is {_session.session_state}"
            )
            if _session.session_state != new_state:
                _session.session_state = new_state
                _session.session_state_latest_change_time = datetime.now(timezone.utc)
                try:
                    db_scoped_session.commit()
                    logger.info(
                        f"Success: state for session {_session.id=} {_session.session_uuid=} to {new_state=} in the database"
                    )
                except Exception as e:
                    db_scoped_session.rollback()
                    logger.critical(
                        f"Error trying to run the following commits on update_virtual_desktop_state because of: {e}"
                    )
                    queries = [
                        str(statement)
                        for statement in db_scoped_session._logger.handlers[
                            0
                        ].baseFilename
                    ]
                    logger.critical(f"Failed SQL query: {queries}")

            else:
                logger.info(
                    f"Session {_session.id=} {_session.session_uuid=} already in state {new_state=}"
                )

        except Exception as err:
            logger.error(
                f"Unable to update state for session {_session.session_uuid} to {new_state}: {err}"
            )
            continue


# main
def virtual_desktops_session_state_watcher():
    logger.info("Scheduled Task: virtual_desktops_session_state_watcher")

    _start_time = time.time()

    # Get all current active VDI
    _all_dcv_sessions = VirtualDesktopSessions.query.filter(
        VirtualDesktopSessions.is_active.is_(True)
    ).all()
    if _all_dcv_sessions:

        # First, we get the latest status for all the instances IDs registered.
        # We create batch requests of up to 100 instance ids.
        _instance_ids_by_state = find_instance_ids_instance_state(
            all_sessions=_all_dcv_sessions
        )

        logger.debug(f"Instance ID by State: {_instance_ids_by_state}")

        if _instance_ids_by_state.get("success") is False:
            logger.critical(
                f"Unable to retrieve instance state for all instances due to {_instance_ids_by_state.get('message')}"
            )

        # Start by creating chunk of 50 VDI sessions maximum (this is the max number of InstanceIds we can pass to some boto3 API call)
        # Keep this limit below 50.
        _chunk_size = 50

        # Create chunk of 50 sessions max
        _chunks_of_sessions = chunked_iterable(_all_dcv_sessions, _chunk_size)

        # Provision 3 workers to run concurrently
        _workers = 3

        use_multi_threads = False  # for future usage

        if use_multi_threads:
            with ThreadPoolExecutor(max_workers=_workers) as executor:
                # Submit each chunk to the executor for parallel processing
                futures = [
                    executor.submit(
                        process_chunk, chunk, _instance_ids_by_state.get("message")
                    )
                    for chunk in _chunks_of_sessions
                ]

                for future in as_completed(futures):
                    try:
                        result = future.result()
                        logger.info(result)
                    except Exception as e:
                        logger.error(f"Chunk processing failed: {e}")
        else:
            # No concurrency, create chunk and process them
            for _chunk in _chunks_of_sessions:
                process_chunk(_chunk, _instance_ids_by_state.get("message"))

        _end_time = time.time()
        logger.info(
            f"Scheduled task completed in {_end_time - _start_time:.2f} seconds for {len(_all_dcv_sessions)} sessions"
        )

    else:
        logger.info("No active virtual desktops found")
