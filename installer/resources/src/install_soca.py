#!/usr/bin/env python3

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

"""
It's recommended to trigger this script via ./soca_installer.sh as python's virtual env and all required
libraries/dependencies will be automatically installed.

If you trigger ./install_soca.py directly, make sure to have all the Python and CDK dependencies installed
"""

try:
    import sys
    import re
    import boto3
    from collections import defaultdict
    import botocore.exceptions
    from requests import get
    from requests.exceptions import RequestException, Timeout, ConnectionError
    from botocore.client import ClientError
    from botocore.exceptions import ProfileNotFound, ValidationError
    from botocore import config
    import shutil
    import urllib3
    import base64
    import getpass
    import yaml
    import json
    import ast
    from yaml.scanner import ScannerError
    from types import SimpleNamespace
    from rich import print
    from rich.console import Console
    from rich.text import Text
    from rich.table import Column, Table
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeRemainingColumn,
        TimeElapsedColumn,
    )

except ImportError:
    print(
        " > You must have 'rich', 'boto3' and 'requests' installed. Run 'pip install boto3 rich requests' first"
    )
    sys.exit(1)
import time
import datetime
import os
import re
import argparse
from shutil import make_archive, copytree

installer_path = "/".join(os.path.dirname(os.path.abspath(__file__)).split("/")[:-3])
sys.path.append(installer_path)
from installer.resources.src.prompt import get_input as get_input
from installer.resources.src.find_existing_resources import FindExistingResource

urllib3.disable_warnings()


def format_byte_size(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def get_install_properties(pathname: str):
    # Retrieve SOCA configuration properties
    print(f"Configuration file path: {pathname}")
    try:
        with open(pathname, "r") as config_file:
            config_parameters = yaml.safe_load(config_file)
    except ScannerError as err:
        print(f"{pathname} is not a valid YAML file. Verify syntax, {err}")
        sys.exit(1)
    except FileNotFoundError:
        print(
            f"{pathname} not found. Make sure the file exist and the path is correct."
        )
        sys.exit(1)
    if config_parameters:
        return config_parameters
    else:
        sys.exit("No parameters were specified.")


def detect_customer_ip():
    # Try to determine the IP of the customer.
    # If IP cannot be determined we will prompt the user to enter the value manually
    check_url = "https://checkip.amazonaws.com/"
    print(
        f"\n====== Trying to detect your IP via {check_url} . Use --client-ip to specify it manually instead ======\n"
    )
    client_ip = False
    try:
        get_client_ip = get(check_url, timeout=15)
        if get_client_ip.status_code == 200:
            client_ip = f"{str(get_client_ip.text).strip()}/32"

        else:
            print(
                f"Unable to automatically determine client IP via {check_url} . Error: {get_client_ip}"
            )
            client_ip = False
    except RequestException as e:
        print(
            f"Unable to automatically determine client IP via {check_url} . Error: {e}"
        )
        client_ip = False
    return client_ip


def build_lambda_dependency(install_directory):
    print("Building Lambda dependency")
    lambda_functions_folders = f"{install_directory}/../functions/"
    for _dir in os.scandir(lambda_functions_folders):
        for filename in os.listdir(_dir):
            if filename == "requirements.txt":
                print(f"Installing Python dependencies for {_dir.path}")
                if (
                    os.system(
                        f"pip3 install --python-version 3.9 -r {_dir.path}/requirements.txt --platform manylinux2014_x86_64 --target={_dir.path} --implementation cp --only-binary=:all: --upgrade"
                    )
                    != 0
                ):
                    print(f"[red] Error during Lambda Dependency")
                    sys.exit(1)


def upload_objects(install_directory, bucket, cluster_id):
    # Upload required assets to customer S3 bucket
    print(f"\n====== Uploading install files to {bucket}/{cluster_id} ======\n")
    dist_directory = f"{install_directory}/../../dist/{cluster_id}/"
    if os.path.isdir(dist_directory):
        print(f"{dist_directory} already exist. Creating a new one for your build")
        shutil.rmtree(dist_directory)
    os.makedirs(dist_directory)
    make_archive(
        f"{dist_directory}soca", "gztar", f"{install_directory}/../../../source/soca"
    )
    copytree(
        f"{install_directory}/../../../source/scripts", f"{dist_directory}scripts/"
    )

    try:
        install_bucket = s3.Bucket(bucket)
        for path, subdirs, files in os.walk(f"{dist_directory}"):
            path = path.replace("\\", "/")
            directory = path.split("/")[-1]
            for file in files:
                if directory:
                    upload_location = f"{cluster_id}/{directory}/{file}"
                else:
                    upload_location = f"{cluster_id}/{file}"
                print(
                    f"[green][+] Uploading {os.path.join(path, file)} to s3://{bucket}/{upload_location} "
                )
                install_bucket.upload_file(os.path.join(path, file), upload_location)

    except Exception as upload_error:
        print(f"[red] Error during upload {upload_error}")


def accepted_aws_resources(region: str) -> dict:
    # Retrieve all AWS resources. Currently only used to find all available SSH keypair
    accepted_values = {}
    try:
        # TODO describe_key_pairs does not have pagination support as of 12 Dec 2023
        # So while this looks bad - it works
        accepted_values["accepted_keypairs"] = {}
        for key in ec2.describe_key_pairs()["KeyPairs"]:
            accepted_values["accepted_keypairs"][key["KeyPairId"]] = key

        if len(accepted_values) == 0:
            print(f"[red] No SSH keys found on this region. Please create one first")
            sys.exit(1)
    except ClientError as err:
        print(
            f"[yellow]Unable to list SSH keys, you will need to enter it manually or give ec2:Describe* IAM permission. {err} "
        )
        accepted_values["accepted_keypairs"] = {}

    return accepted_values


def check_bucket_name_and_permission(bucket: str) -> bool:

    # Check for None
    if bucket is None:
        # print(f"[red]Invalid S3 bucket name: (NoneType encountered)[/red]")
        return False

    # Check bucket naming before sending to the API
    # Rules are based on: https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    # NOTE - if the bucket requires a dot (.) - modify the regex
    _s3_bucket_re = r'(?!(^(xn--|sthree-|sthree-configurator)|.+(-s3alias|--ol-s3)$))^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'

    if not re.match(_s3_bucket_re, bucket):
        print(f"[red]Invalid S3 bucket name: ({bucket}). Must match Regular Expression: {_s3_bucket_re}[/red]")
        return False

    # Check if user has permission to the S3 bucket specified
    try:
        s3.meta.client.head_bucket(Bucket=bucket)
        return True
    except ClientError as e:
        print(f"[red]The S3 bucket ({bucket}) does not exist or you have do not have permissions: {e}[/red]")
        return False
    except botocore.exceptions.ParamValidationError as e:
        print(f"[red]The S3 bucket ({bucket}) is invalid: {e}[/red]")
        return False
    except Exception as e:
        print(f"[red]Error during bucket permission check: {e}[/red]")
        return False



def default_ldap_user_password():
    # Manage primary LDAP user/password
    restricted_chars = ["'", '"', "=", ";", ",", "$", "`", "~", "%", " "]
    password_regex = r"^(?:(?=.*[a-z])(?:(?=.*[A-Z])(?=.*[\d\W])|(?=.*\W)(?=.*\d))|(?=.*\W)(?=.*[A-Z])(?=.*\d)).{8,}$"
    if args.ldap_password_file is None:
        install_parameters["ldap_password"] = get_input(
            f"[Step 4/{total_install_phases}] {install_phases[4]}",
            args.ldap_password,
            None,
            str,
            hide=True,
        )
        while (
            not install_parameters.get("ldap_password", None)
            or not re.match(password_regex, install_parameters["ldap_password"])
            or install_parameters["ldap_user"].lower()
            in install_parameters["ldap_password"].lower()
            or [
                element
                for element in restricted_chars
                if (element in install_parameters["ldap_password"])
            ]
        ):
            print(
                f"[red] LDAP password must have 1 uppercase, 1 lowercase, 1 digit and be 8 chars min.\n LDAP password cannot contain your username, white space, or any of the following special characters {''.join(restricted_chars)}"
            )
            install_parameters["ldap_password"] = get_input(
                f"[Step 4/{total_install_phases}] {install_phases[4]}",
                None,
                None,
                str,
                hide=True,
            )

        if not args.ldap_password:
            # when pw is entered interactively via getpass, we ask for a verification
            ldap_password_verify = get_input(
                "[Verification] Please re-enter the password of your first LDAP account",
                args.ldap_password,
                None,
                str,
                hide=True,
            )
            if install_parameters["ldap_password"] != ldap_password_verify:
                print(
                    f"[red] You entered two different passwords. Please try again and make sure password and password (verification) are the same."
                )
                return False
            else:
                return True
    else:
        # Retrieve password from file
        print(f"[yellow]Retrieving password from {args.ldap_password_file}")
        try:
            with open(args.ldap_password_file) as f:
                install_parameters["ldap_password"] = (
                    f.read().replace("\n", "").replace("\r", "")
                )
                if not re.match(password_regex, install_parameters["ldap_password"]):
                    print(
                        f"[red] LDAP password must have 1 uppercase, 1 lowercase, 1 digit and be 8 char min"
                    )
                    sys.exit(1)
        except FileNotFoundError:
            print(
                f"[red]Unable to found {args.ldap_password_file}. Please specify absolute path "
            )
            sys.exit(1)


def _get_filesystems_by_vpc(region: str, vpc_id: str) -> dict:
    console = Console(record=True)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        "Elapsed:",
        TimeElapsedColumn(),
    ) as progress:
        filesystems = {}
        count = 1

        efs_task = progress.add_task("Discovering EFS filesystems", start=False)
        fsx_task = progress.add_task("Discovering FSx filesystems", start=False)

        progress.start_task(efs_task)
        progress.console.log(
            f"[bold green]Retrieving EFS Filesystems from {region}/{vpc_id} ...[/bold green]"
        )

        efs_paginator = efs.get_paginator("describe_file_systems")
        efs_iterator = efs_paginator.paginate()

        for page in efs_iterator:
            for filesystem in page["FileSystems"]:
                _fs_id: str = filesystem.get("FileSystemId", "unknown")

                # Shouldn't happen
                if _fs_id == "unknown":
                    progress.console.log(f"[yellow] Skipping filesystem {_fs_id}")
                    continue

                # check for lifecycle
                if filesystem.get("LifeCycleState", "unknown").upper() not in {"AVAILABLE"}:
                    progress.console.log(
                        f"[yellow]Skipping EFS {_fs_id} - filesystem Lifecycle is not ready (must be AVAILABLE)[/yellow]"
                    )
                    continue

                verified_vpc = False

                _mount_target_count: int = filesystem.get("NumberOfMountTargets", 0)
                if _mount_target_count <= 0:
                    progress.console.log(f"[yellow]Skipping EFS filesystem {_fs_id} - no mount targets available[/yellow]")
                    continue

                progress.console.log(f"[cyan]Processing mount targets for EFS {_fs_id}[/cyan]")
                mount_targets = efs.describe_mount_targets(
                    FileSystemId=_fs_id
                )["MountTargets"]

                for mount_target in mount_targets:

                    time.sleep(0.100)  # Prevent Throttle Exceptions that can take place in dense EFS environments
                    if mount_target["VpcId"] == vpc_id:
                        verified_vpc = True

                if verified_vpc is True:
                    _fs_name: str = (
                        filesystem["Name"] if "Name" in filesystem.keys() else "EFS: "
                    )
                    _fs_size: int = filesystem.get("SizeInBytes", {}).get("Value", 0)
                    _fs_size_str: str = format_byte_size(_fs_size)
                    progress.console.log(
                        f"[cyan]Discovered EFS filesystem {_fs_id} ({_fs_name}) ({_fs_size_str})[/cyan]"
                    )

                    # Populate features for EFS
                    _fs_perf_mode: str = filesystem.get("PerformanceMode", "unknown")
                    _fs_features_str: str = ""

                    if _fs_perf_mode == "generalPurpose":
                        _fs_throughputmode = filesystem.get("ThroughputMode", "unknown")

                        if _fs_throughputmode == "provisioned":
                            _fs_throughput_rate: float = filesystem.get("ProvisionedThroughputInMibps", 0.0)
                            _fs_features_str = f"GP/Provisioned/{_fs_throughput_rate} MiB/s"
                        else:
                            _fs_features_str = f"GP/" + filesystem.get("ThroughputMode", "unknown").capitalize()

                    else:
                        progress.console.log(f"[red]Skipping Filesystem - Unknown performance mode for filesystem {_fs_id} ({_fs_name})[/red]")
                        continue

                    # TODO alternate partition DNS suffix determination
                    _fs_id_fqdn: str = f"{_fs_id}.efs.{region}.amazonaws.com"

                    if filesystem["FileSystemId"]:
                        filesystems[count] = {
                            "id": _fs_id,
                            "name": _fs_id_fqdn,
                            "size": _fs_size_str,
                            "fs_type": "efs",
                            "description": f"{_fs_name} {_fs_id_fqdn}",
                            "features": _fs_features_str,
                        }
                        count += 1

        efs_count = count - 1

        progress.console.log(
            f"[bold green]Retrieving FSx Filesystems from {region}/{vpc_id} ...[/bold green]"
        )
        progress.start_task(fsx_task)
        fsx_paginator = fsx.get_paginator("describe_file_systems")
        fsx_iterator = fsx_paginator.paginate()

        for page in fsx_iterator:
            for filesystem in page["FileSystems"]:
                # Check for proper Lifecycle
                _fs_lifecycle: str = filesystem.get("Lifecycle", "unknown-lifecycle")
                if _fs_lifecycle.upper() not in {
                    "AVAILABLE",
                    "UPDATING",
                }:
                    progress.console.log(
                        f"[yellow]Skipping FSx filesystem {filesystem['FileSystemId']} ({fsx_type}) - filesystem Lifecycle is not ready (status {_fs_lifecycle})[/yellow]"
                    )
                    continue

                fsx_type = filesystem.get("FileSystemType", "unknown-type")

                # TODO - Add more FSx support here
                # if fsx_type.upper() not in {'WINDOWS', 'LUSTRE', 'ONTAP', 'OPENZFS'}:
                if fsx_type.upper() not in {"LUSTRE", "OPENZFS"}:
                    progress.console.log(
                        f"[yellow]Skipping unsupported FSx type ({fsx_type}) for {filesystem['FileSystemId']}[/yellow]"
                    )
                    continue

                # Skip filesystems we have selected and ones that do not match our VPC
                if filesystem.get("VpcId", "") != vpc_id:
                    progress.console.log(
                        f"[yellow]Skipping FSx {filesystem['FileSystemId']} - not in our VPC[/yellow]"
                    )
                    continue

                _fs_size_str: str = format_byte_size(
                    num=filesystem.get("StorageCapacity", 0) * 1024 * 1024 * 1024
                )

                resource_name = ""
                for tag in filesystem["Tags"]:
                    if tag["Key"] == "Name":
                        resource_name = tag["Value"]

                if not resource_name:
                    resource_name = "unnamed"

                progress.console.log(
                    f"[cyan]Discovered FSx/{fsx_type.capitalize()} filesystem {filesystem['FileSystemId']} ({resource_name}) ({_fs_size_str})[/cyan]"
                )

                _dns_name: str = filesystem.get("DNSName", "UnknownDNS")

                _fs_features_str: str = ""

                if fsx_type.upper() in {"OPENZFS", "LUSTRE"}:
                    _key: str = "LustreConfiguration" if fsx_type.upper() == "LUSTRE" else "OpenZFSConfiguration"
                    _deployment_type: str = filesystem.get(_key, {}).get("DeploymentType", "Unknown")
                    if _deployment_type != "Unknown":
                        _fs_features_str += _deployment_type

                # Other filesystems may use this later - for now only Lustre seems to populate this
                _fs_version: str = filesystem.get("FileSystemTypeVersion", "")
                if _fs_version:
                    _fs_features_str += f"\nVersion: {_fs_version}"

                filesystems[count] = {
                    "id": f"{filesystem['FileSystemId']}",
                    "name": resource_name,
                    "dns_name": _dns_name,
                    "size": _fs_size_str,
                    "fs_type": f"fsx_{fsx_type.lower()}",
                    "description": f"FSx/{fsx_type.upper()}: {resource_name if resource_name else f'FSx/{fsx_type.upper()}: '} {_dns_name}",
                    "features": _fs_features_str,
                }
                count += 1

    return filesystems


def get_install_parameters():
    # Retrieve User Specified Variables
    print(
        "\n====== Validating [red]S[blue]O[magenta]C[yellow]A[default] Parameters ======\n"
    )

    install_parameters["cluster_name"] = get_input(
        f"[Step 1/{total_install_phases}] {install_phases[1]}", args.name, None, str
    )
    while (
        len(install_parameters["cluster_name"]) < 3
        or len(install_parameters["cluster_name"]) > 11
    ):
        print(
            f"[red]SOCA cluster name must greater than 3 chars and shorter than 11 characters (soca- is automatically added as a prefix) "
        )
        install_parameters["cluster_name"] = get_input(
            f"[Step 1/{total_install_phases}] {install_phases[1]}", None, None, str
        )

    # Sanitize cluster name (remove any non-alphanumerical character) or generate random cluster identifier
    sanitized_cluster_id = re.sub(r"\W+", "-", install_parameters["cluster_name"])
    sanitized_cluster_id = re.sub(
        r"soca-", "", sanitized_cluster_id
    )  # remove soca- if specified by the user
    install_parameters[
        "cluster_id"
    ] = f"soca-{sanitized_cluster_id.lower()}"  # do not remove soca- prefix or DCV IAM permission will not be working.

    install_parameters["bucket"] = get_input(
        prompt=f"[Step 2/{total_install_phases}] {install_phases[2]}",
        specified_value=args.bucket,
        expected_answers=None,
        expected_type=str
    )

    while check_bucket_name_and_permission(install_parameters["bucket"]) is False:
        install_parameters["bucket"] = get_input(
            f"[Step 2/{total_install_phases}] {install_phases[2]}", None, None, str
        )

    install_parameters["ldap_user"] = get_input(
        f"[Step 3/{total_install_phases}] {install_phases[3]}",
        args.ldap_user,
        None,
        str,
    )
    while (
        len(install_parameters["ldap_user"]) < 5
        or not install_parameters["ldap_user"].isalnum()
    ):
        print(
            f"[red]LDAP user must be 5 characters mins and can only contains alphanumeric."
        )
        install_parameters["ldap_user"] = get_input(
            f"[Step 3/{total_install_phases}] {install_phases[3]}", None, None, str
        )

    if install_props.Config.directoryservice.provider == "activedirectory":
        while install_parameters["ldap_user"].lower() == "admin":
            print(
                f"[yellow] To prevent conflict with Directory Service, the first SOCA user cannot be named admin. Please pick a different name."
            )
            install_parameters["ldap_user"] = get_input(
                f"[Step 3/{total_install_phases}] {install_phases[3]}", None, None, str
            )

    create_ldap_user = default_ldap_user_password()
    while create_ldap_user is False:
        create_ldap_user = default_ldap_user_password()

    # Encode password to avoid any special char error while running bash CDK
    install_parameters["ldap_password"] = (
        base64.b64encode(install_parameters["ldap_password"].encode("utf-8"))
    ).decode("utf-8")
    install_parameters["base_os"] = get_input(
        prompt=f"[Step 5/{total_install_phases}] {install_phases[5]}",
        specified_value=args.base_os,
        expected_answers={
            "amazonlinux2": {"visible": True},
            "centos7": {"visible": False},
            "rhel7": {"visible": False},
        },
        expected_type=str,
        show_expected_answers=True,
    )

    keypair_table = Table(title=f"SSH Key Pairs", show_lines=True, highlight=True)

    keypair_table.add_column("#", justify="center", width=4, no_wrap=True)
    keypair_table.add_column("Keypair ID", justify="center", width=21, no_wrap=True)
    keypair_table.add_column("Name", justify="center", width=32, no_wrap=True)
    keypair_table.add_column("Creation", justify="center")
    keypair_table.add_column("Fingerprint", justify="center", no_wrap=True)

    _kp_n = 1
    # print(f"DEBUg - keypairs: {accepted_aws_values['accepted_keypairs']}")
    _kp_map = {}

    for keypair in accepted_aws_values["accepted_keypairs"]:
        _key_id_str: str = accepted_aws_values["accepted_keypairs"][keypair].get(
            "KeyPairId"
        )
        _key_name_str: str = accepted_aws_values["accepted_keypairs"][keypair].get(
            "KeyName"
        )
        _key_type_str: str = accepted_aws_values["accepted_keypairs"][keypair].get(
            "KeyType"
        )
        _key_creation_date_str: str = str(
            accepted_aws_values["accepted_keypairs"][keypair].get("CreateTime")
        )
        _key_fingerprint_str: str = accepted_aws_values["accepted_keypairs"][
            keypair
        ].get("KeyFingerprint")
        if _kp_n not in _kp_map:
            _kp_map[_kp_n] = {}

        _kp_map[_kp_n] = {
            "KeyIndex": _kp_n,  # This is just our running tally
            "KeyPairId": _key_id_str,
            "KeyName": _key_name_str,
            "KeyFingerprint": _key_fingerprint_str,
            "KeyType": _key_type_str,
        }

        keypair_table.add_row(
            str(_kp_n),
            _key_id_str,
            f"{_key_name_str} ({_key_type_str})",
            _key_creation_date_str,
            _key_fingerprint_str,
        )
        _kp_n += 1

    _selected_key_name: str = ""
    _spec_value_str: str = ""

    if args.ssh_keypair:
        _spec_value_str = next(
            (
                v.get("KeyName")
                for k, v in _kp_map.items()
                if v.get("KeyName") == args.ssh_keypair
            ),
            "",
        )

        if not _spec_value_str:
            print(
                f"[red]WARNING: Keypair {args.ssh_keypair} not found. Please confirm region and select a keypair"
            )
        else:
            _selected_key_name = _spec_value_str

    if not _selected_key_name:
        # make sure we don't draw emojis in SSH fingerprints
        _console = Console(emoji=False)
        _console.print(keypair_table)

        _keypair_selection = get_input(
            prompt=f"[Step 6/{total_install_phases}] {install_phases[6]}",
            specified_value=None,
            expected_answers=[str(_i) for _i in range(1, _kp_n)],
            expected_type=int,
            show_expected_answers=False,
            show_default_answer=False,
        )
        # print(f"DEBUG: Keypair selection: {_keypair_selection}")
        _spec_value_str = next(
            (
                v.get("KeyName")
                for k, v in _kp_map.items()
                if v.get("KeyIndex") == _keypair_selection
            ),
            "",
        )
        # print(f"DEBUG: Keypair selection _spec_value_str:  {_spec_value_str} - KeyMap: {_kp_map}")

    _selected_key_name = _spec_value_str

    # print(f"DEBUG - Final keypair name: {_selected_key_name} from {_spec_value_str}")
    install_parameters["ssh_keypair"] = _selected_key_name

    # Validate the prefix list id
    if args.prefix_list_id:
        try:
            found_prefix_list_id = ec2.describe_managed_prefix_lists(
                PrefixListIds=[args.prefix_list_id]
            )["PrefixLists"][0]["PrefixListId"]
            if found_prefix_list_id != args.prefix_list_id:
                raise RuntimeError(
                    f"Found prefix list {found_prefix_list_id} does not match {args.prefix_list_id}. This is a programming error; please create an issue."
                )
            else:
                install_parameters["prefix_list_id"] = args.prefix_list_id
        except Exception as e:
            print(
                f"[red]Error. {args.prefix_list_id} not found. Check that it exists and starts with pl-.\nException:\n{e} "
            )
            sys.exit(1)

    install_parameters["custom_ami"] = args.custom_ami if args.custom_ami else None

    # Network Configuration
    cidr_regex = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$"
    if not args.vpc_cidr:
        choice_vpc = get_input(
            f"[Step 7/{total_install_phases}] {install_phases[7]}",
            None,
            ["new", "existing"],
            str,
        )
        if choice_vpc == "new":
            install_parameters["vpc_cidr"] = get_input(
                "What CIDR do you want to use for your VPC? We recommend 10.0.0.0/16",
                args.vpc_cidr,
                None,
                str,
            )
            while not re.match(cidr_regex, install_parameters["vpc_cidr"]):
                print(
                    f"[red] Invalid CIDR {install_parameters['vpc_cidr']}. Format must be x.x.x.x/x (eg: 10.0.0.0/16)"
                )
                install_parameters["vpc_cidr"] = get_input(
                    "What CIDR do you want to use for your VPC? We recommend 10.0.0.0/16",
                    None,
                    None,
                    str,
                )
        else:
            # List all VPCs running on AWS account
            existing_vpc = FindExistingResource(
                install_parameters["region"], install_parameters["client_ip"]
            ).find_vpc()

            if existing_vpc["success"] is True:
                install_parameters["vpc_id"] = existing_vpc["message"]["id"]
                install_parameters["vpc_cidr"] = existing_vpc["message"]["cidr"]
            else:
                print(f"Unable to find VPC - exiting...")
                sys.exit(1)

            # List all Subnets
            if install_props.Config.entry_points_subnets.lower() == "public":
                public_subnets = FindExistingResource(
                    install_parameters["region"], install_parameters["client_ip"]
                ).get_subnets(install_parameters["vpc_id"], "public", [])
                if public_subnets["success"] is True:
                    install_parameters["public_subnets"] = base64.b64encode(
                        str(public_subnets["message"]).encode("utf-8")
                    ).decode("utf-8")
                else:
                    print(f"[red]Error: {public_subnets['message']} ")
                    sys.exit(1)
            else:
                public_subnets = {"success": False, "message": []}
                install_parameters["public_subnets"] = base64.b64encode(
                    str(public_subnets["message"]).encode("utf-8")
                ).decode("utf-8")

            private_subnets = FindExistingResource(
                install_parameters["region"], install_parameters["client_ip"]
            ).get_subnets(install_parameters["vpc_id"], "private", [])
            if private_subnets["success"] is True:
                install_parameters["private_subnets"] = base64.b64encode(
                    str(private_subnets["message"]).encode("utf-8")
                ).decode("utf-8")
            else:
                print(f"[red]Error: {private_subnets['message']} ")
                sys.exit(1)

            vpc_azs = []
            for subnet in public_subnets["message"] + private_subnets["message"]:
                az = subnet.split(",")[1]
                if az not in vpc_azs:
                    vpc_azs.append(az)

                install_parameters["vpc_azs"] = ",".join(vpc_azs)
    else:
        install_parameters["vpc_cidr"] = args.vpc_cidr
        while not re.match(cidr_regex, install_parameters["vpc_cidr"]):
            print(
                f"[red] Invalid CIDR {install_parameters['vpc_cidr']}. Format must be x.x.x.x/x (eg: 10.0.0.0/16)"
            )
            install_parameters["vpc_cidr"] = get_input(
                "What CIDR do you want to use for your VPC? We recommend 10.0.0.0/16",
                None,
                None,
                str,
            )
    # Security Groups Configuration (only possible if user installs to an existing VPC)
    if install_parameters["vpc_id"]:
        choice_security_groups = get_input(
            f"[Step 8/{total_install_phases}] {install_phases[8]}",
            None,
            ["new", "existing"],
            str,
        )
        if choice_security_groups == "existing":
            scheduler_sg = FindExistingResource(
                install_parameters["region"], install_parameters["client_ip"]
            ).get_security_groups(install_parameters["vpc_id"], "scheduler", [])
            if scheduler_sg["success"] is True:
                install_parameters["scheduler_sg"] = scheduler_sg["message"]
            else:
                print(f"[red]Error: {scheduler_sg['message']} ")
                sys.exit(1)

            compute_node_sg = FindExistingResource(
                install_parameters["region"], install_parameters["client_ip"]
            ).get_security_groups(
                install_parameters["vpc_id"],
                "compute nodes",
                install_parameters["scheduler_sg"],
            )
            if compute_node_sg["success"] is True:
                install_parameters["compute_node_sg"] = compute_node_sg["message"]
            else:
                print(f"[red]Error: {compute_node_sg['message']} ")
                sys.exit(1)

            if install_props.Config.network.vpc_interface_endpoints:
                vpc_endpoint_sg = FindExistingResource(
                    install_parameters["region"], install_parameters["client_ip"]
                ).get_security_groups(
                    install_parameters["vpc_id"],
                    "vpc endpoints",
                    install_parameters["scheduler_sg"],
                )
                if vpc_endpoint_sg["success"] is True:
                    install_parameters["vpc_endpoint_sg"] = vpc_endpoint_sg["message"]
                else:
                    print(f"[red]Error: {vpc_endpoint_sg['message']} ")
                    sys.exit(1)
            else:
                vpc_endpoint_sg = None

    # Filesystem Configuration (only possible if user installs to an existing VPC)
    if install_parameters["vpc_id"]:
        choice_filesystem = get_input(
            f"[Step 9/{total_install_phases}] {install_phases[9]}",
            None,
            ["new", "existing"],
            str,
        )
        if choice_filesystem == "existing":
            # TODO - This needs to be reworked to poll the account _once_ versus for each get_fs() call.
            # As this makes it very slow for big / populated VPCs/accounts
            # List FS

            _selected_fs = []
            _filesystems_in_vpc = _get_filesystems_by_vpc(
                region=install_parameters["region"], vpc_id=install_parameters["vpc_id"]
            )

            fs_apps = FindExistingResource(
                install_parameters["region"], install_parameters["client_ip"]
            ).get_fs(
                environment="/apps",
                vpc_id=install_parameters["vpc_id"],
                filesystems=_filesystems_in_vpc,
            )

            if fs_apps["success"] is True:
                install_parameters["fs_apps_provider"] = fs_apps["provider"]
                install_parameters["fs_apps"] = fs_apps["message"]
                _selected_fs.append(fs_apps["message"])
            else:
                print(f"[red]Error: {fs_apps['message']} ")
                sys.exit(1)

            # Trim down the /data options after /apps is selected
            _filesystems_in_vpc = {
                k: v
                for k, v in _filesystems_in_vpc.items()
                if v["id"] not in _selected_fs
            }

            fs_data = FindExistingResource(
                install_parameters["region"], install_parameters["client_ip"]
            ).get_fs(
                environment="/data",
                vpc_id=install_parameters["vpc_id"],
                filesystems=_filesystems_in_vpc,
                selected_fs=_selected_fs,
            )

            if fs_data["success"] is True:
                install_parameters["fs_data_provider"] = fs_data["provider"]
                install_parameters["fs_data"] = fs_data["message"]
                # TODO - this should no longer be possible?
                if install_parameters["fs_data"] == install_parameters["fs_apps"]:
                    print(
                        f"[red]Error: Filesystem choice for /apps and /data must be different "
                    )
                    sys.exit(1)
            else:
                print(f"[red]Error: {fs_data['message']} ")
                sys.exit(1)

    # Verify SG permissions
    if install_parameters["fs_apps"] or install_parameters["scheduler_sg"]:
        FindExistingResource(
            install_parameters["region"], install_parameters["client_ip"]
        ).validate_sg_rules(
            install_parameters,
            check_fs=True if install_parameters["fs_apps"] else False,
        )

    # AWS Directory Service Managed Active Directory configuration (only possible when using existing VPC)
    if install_props.Config.directoryservice.provider == "activedirectory":
        if install_parameters["vpc_id"]:
            choice_mad = get_input(
                f"[Step 10/{total_install_phases}] {install_phases[10]}",
                None,
                ["new", "existing"],
                str,
            )
            if choice_mad == "existing":
                directory_service = FindExistingResource(
                    install_parameters["region"], install_parameters["client_ip"]
                ).find_directory_services(install_parameters["vpc_id"])
                if directory_service["success"] is True:
                    install_parameters["directory_service_ds_user"] = get_input(
                        f"Username of a domain user with  admin permissions?",
                        None,
                        None,
                        str,
                    )
                    install_parameters[
                        "directory_service_ds_user_password"
                    ] = get_input(
                        f"Password of the domain user with admin permissions",
                        None,
                        None,
                        str,
                    )
                    install_parameters["directory_service"] = directory_service[
                        "message"
                    ]["id"]
                    install_parameters[
                        "directory_service_shortname"
                    ] = directory_service["message"]["netbios"]
                    install_parameters["directory_service_name"] = directory_service[
                        "message"
                    ]["name"]
                    install_parameters["directory_service_dns"] = directory_service[
                        "message"
                    ]["dns"]
                else:
                    print(f"[red]Error: {directory_service['message']} ")
                    sys.exit(1)

    # ElasticSearch Configuration (only possible when using existing VPC)
    if install_parameters["vpc_id"]:
        choice_es = get_input(
            f"[Step 11/{total_install_phases}] {install_phases[11]}",
            None,
            ["new", "existing"],
            str,
        )

        if choice_es == "existing":
            elasticsearch_cluster = FindExistingResource(
                install_parameters["region"], install_parameters["client_ip"]
            ).find_elasticsearch(install_parameters["vpc_id"])

            if elasticsearch_cluster["success"] is True:
                install_parameters["os_domain"] = elasticsearch_cluster["message"][
                    "endpoint"
                ]
                install_parameters["os_endpoint"] = elasticsearch_cluster["message"][
                    "endpoint"
                ]
            else:
                print(f"[red]Error: {elasticsearch_cluster['message']} ")
                sys.exit(1)
    else:
        install_parameters["os_domain"] = None

    # IAM Roles configuration (only possible when using existing VPC)
    if install_parameters["vpc_id"]:
        choice_iam_roles = get_input(
            f"[Step 12/{total_install_phases}] {install_phases[12]}",
            None,
            ["new", "existing"],
            str,
        )
        if choice_iam_roles == "existing":
            scheduler_role = FindExistingResource(
                install_parameters["region"], install_parameters["client_ip"]
            ).get_iam_roles("scheduler")
            if scheduler_role["success"] is True:
                install_parameters["scheduler_role_name"] = scheduler_role["message"][
                    "name"
                ]
                install_parameters["scheduler_role_arn"] = scheduler_role["message"][
                    "arn"
                ]
            else:
                print(f"[red]Error: {scheduler_role['message']} ")
                sys.exit(1)

            if (
                get_input(
                    f"Was this role generated by a previous SOCA deployment? If yes, are you also using the same S3 bucket?",
                    None,
                    ["yes", "no"],
                    str,
                )
                == "yes"
            ):
                install_parameters[
                    "scheduler_role_from_previous_soca_deployment"
                ] = True
            else:
                get_input(
                    f"[IMPORTANT] Make sure this role is assumed by 'ec2.amazon.com' and 'ssm.amazonaws.com'\n Type ok to continue ...",
                    None,
                    ["ok"],
                    str,
                    color="yellow",
                )

            compute_node_role = FindExistingResource(
                install_parameters["region"], install_parameters["client_ip"]
            ).get_iam_roles(
                "compute nodes",
                selected_roles=[install_parameters["scheduler_role_name"]],
            )
            if compute_node_role["success"] is True:
                install_parameters["compute_node_role_name"] = compute_node_role[
                    "message"
                ]["name"]
                install_parameters["compute_node_role_arn"] = compute_node_role[
                    "message"
                ]["arn"]
            else:
                print(f"[red]Error: {compute_node_role['message']} ")
                sys.exit(1)

            if (
                get_input(
                    f"Was this role generated by a previous SOCA deployment?",
                    None,
                    ["yes", "no"],
                    str,
                )
                == "yes"
            ):
                install_parameters[
                    "compute_node_role_from_previous_soca_deployment"
                ] = True
            else:
                get_input(
                    f"[IMPORTANT] Make sure this role is assumed by 'ec2.amazon.com' and 'ssm.amazonaws.com'\n Type ok to continue ...",
                    None,
                    ["ok"],
                    str,
                    color="yellow",
                )

            spotfleet_role = FindExistingResource(
                install_parameters["region"], install_parameters["client_ip"]
            ).get_iam_roles(
                "spot fleet",
                selected_roles=[
                    install_parameters["scheduler_role_name"],
                    install_parameters["compute_node_role_name"],
                ],
            )
            if spotfleet_role["success"] is True:
                install_parameters["spotfleet_role_name"] = spotfleet_role["message"][
                    "name"
                ]
                install_parameters["spotfleet_role_arn"] = spotfleet_role["message"][
                    "arn"
                ]
            else:
                print(f"[red]Error: {spotfleet_role['message']} ")
                sys.exit(1)

            if (
                get_input(
                    f"Was this role generated by a previous SOCA deployment?",
                    None,
                    ["yes", "no"],
                    str,
                )
                == "yes"
            ):
                install_parameters[
                    "spotfleet_role_from_previous_soca_deployment"
                ] = True
            else:
                get_input(
                    f"[IMPORTANT] Make sure this role is assumed by 'spotfleet.amazonaws.com'\n Type ok to continue ...",
                    None,
                    ["ok"],
                    str,
                    color="yellow",
                )


def validate_soca_config(user_specified_inputs, install_properties):
    # We run one final validation check at the end, comparing the installation properties from config.yml and user inputs
    print("\n====== Verifying SOCA Configuration  ======\n")
    errors = []
    exit_installer = False  # Installer will exit if user has invalid default_config.yml params that require a file edit

    if user_specified_inputs["vpc_id"]:
        private_subnets = ast.literal_eval(
            base64.b64decode(user_specified_inputs["private_subnets"]).decode("utf-8")
        )
        private_subnet_azs = [
            k.split(",")[1] for k in private_subnets if k.split(",")[1]
        ]
        public_subnets = ast.literal_eval(
            base64.b64decode(user_specified_inputs["public_subnets"]).decode("utf-8")
        )
        public_subnet_azs = [k.split(",")[1] for k in public_subnets]

    # if AZ is = 2, check if ES data nodes is 1,2 or a multiple. No restriction when using > 3 AZs
    if not user_specified_inputs["es_domain"]:
        if user_specified_inputs["vpc_id"]:
            max_azs = len(list(dict.fromkeys(private_subnet_azs)))
        else:
            max_azs = install_properties.Config.network.max_azs

        if max_azs == 2:
            # No limitation when using 3 or more AZs. 1 is not an option here
            data_nodes = install_properties.Config.analytics.data_nodes
            if (data_nodes % 2) == 0 or data_nodes <= 2:
                pass
            else:
                errors.append(
                    "Config > ElasticSearch > data_nodes must be 1,2 or a multiple of 2."
                )
                exit_installer = True

    if user_specified_inputs["vpc_id"]:
        # Validate network configuration when using a custom VPC
        if len(list(dict.fromkeys(private_subnet_azs))) == 1:
            errors.append(
                f"Your private subnets are only configured to use a single AZ ({private_subnet_azs}). You must use at least 2 AZs for HA"
            )
        if len(list(dict.fromkeys(public_subnet_azs))) == 1:
            errors.append(
                f"Your public subnets are only configured to use a single AZ ({public_subnet_azs}). You must use at least 2 AZs for HA"
            )
    else:
        # check if az is min 2
        if install_properties.Config.network.max_azs < 2:
            errors.append("Config > Network > max_azs must be at least 2")
            exit_installer = True

    if not errors:
        print(f"[green]Configuration valid. ")
        return True
    else:
        for message in errors:
            print(f"[red]- {message} ")

        print(
            f"[red]\n /!! Unable to validate configuration. Please fix the errors listed above and try again. "
        )
        if exit_installer is True:
            sys.exit(1)
        else:
            return False


def override_keys(keys_to_override, install_properties):
    override_mapping: dict = {}
    _config_table = Table(title=f"Detected CLI Configuration Overrides", show_lines=True, highlight=True)
    _config_table.add_column(header="Key", justify="left", width=30, no_wrap=True)
    _config_table.add_column(header="Type", justify="left", width=10, no_wrap=True)
    _config_table.add_column(header="Value", justify="left", width=20, no_wrap=True)

    for key in keys_to_override:
        # print(f"Detected Key Override: {key}")
        override_info = key.split(",")
        if len(override_info) != 3:
            print(
                f"Override information must use the following format: '<key_name>,<type>,<new_value>' (ex: Config.termination_protection,Bool,False). Detected {key}"
            )
            sys.exit(1)
        else:
            key_name = override_info[0]
            value_type = override_info[1]
            key_value = override_info[2]

            if value_type.lower() in ("bool", "boolean"):
                if key_value.lower() == "true":
                    key_value = True
                elif key_value.lower() == "false":
                    key_value = False
                else:
                    print(
                        f"{key} does not seems to be a valid boolean. Please specify either True or False."
                    )
                    sys.exit(1)
            elif value_type.lower() in ("str", "string"):
                key_value = str(key_value)
            elif value_type.lower() in ("list"):
                key_value = key_value.split("+")
            elif value_type.lower() in ("int", "integer"):
                try:
                    key_value = int(key_value)
                except ValueError:
                    print(f"Expected {value_type} but detected {key_value}")
                    sys.exit(1)
            else:
                print(
                    f"Value type must be bool/boolean/str/string/int/integer/list. Detected {value_type.lower()}"
                )
                sys.exit(1)
        _config_table.add_row(
            str(key_name),
            str(value_type),
            str(key_value),
        )
        override_mapping[key_name] = key_value

    print(_config_table)
    # Parse the JSON into a Python dictionary
    for key, value in override_mapping.items():
        # Split the key into individual keys
        keys = key.split(".")
        # Traverse through the nested dictionaries and update the value
        temp_dict = install_properties
        for k in keys[:-1]:
            temp_dict = temp_dict[k]

        temp_dict[keys[-1]] = value

    return install_properties


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create SOCA installer. Visit https://awslabs.github.io/scale-out-computing-on-aws/tutorials/install-soca-cluster/ if you need help"
    )
    parser.add_argument(
        "--profile",
        "-p",
        type=str,
        help="AWS CLI profile to use. See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html",
    )
    parser.add_argument(
        "--region",
        "-r",
        type=str,
        help="AWS region where you want to deploy your SOCA environment.",
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default=f"{os.path.dirname(os.path.realpath(__file__))}/../../default_config.yml",
        help="Path of custom config file. Default to default_config.yml",
    )
    parser.add_argument("--bucket", "-b", type=str, help="S3 Bucket to use")
    parser.add_argument(
        "--ldap-user",
        "-lu",
        type=str,
        help="Username of your first ldap user. This user has admin privileges",
    )
    parser.add_argument(
        "--ldap-password", "-lp", type=str, help="Password for your first ldap user"
    )
    parser.add_argument(
        "--ldap-password-file",
        "-lpf",
        type=str,
        help="Path to a file containing your password",
    )
    parser.add_argument("--ssh-keypair", "-ssh", type=str, help="SSH key to use")
    parser.add_argument("--custom-ami", "-ami", type=str, help="Specify a custom image")
    parser.add_argument(
        "--vpc-cidr",
        "-cidr",
        type=str,
        help="What CIDR do you want to use for your VPC (eg: 10.0.0.0/16)",
    )
    parser.add_argument(
        "--client-ip",
        "-ip",
        type=str,
        help="Client IP authorized to access SOCA on port 22/443",
    )
    parser.add_argument(
        "--prefix-list-id",
        "-pl",
        type=str,
        help="Prefix list ID with IPs authorized to access SOCA on port 22/443",
    )
    parser.add_argument(
        "--name",
        "-n",
        type=str,
        help="Friendly name for your SOCA cluster. Must be unique in the region. SOCA will be added as prefix",
    )
    parser.add_argument(
        "--override",
        type=str,
        action="append",
        nargs="+",
        help="Configuration key(s) to override. Syntax is '<key_name>,<type>,<value>'. You can use multiple --override if needed.",
    )
    parser.add_argument(
        "--base-os",
        "-os",
        choices=[
            "amazonlinux2",
            "amazonlinux2023",
            "centos7",
            "rhel7",
            "rhel8",
            "rhel9",
        ],
        type=str,
        help="The preferred Linux distribution for the scheduler and compute instances",
    )
    parser.add_argument(
        "--debug",
        action="store_const",
        const=True,
        default=False,
        help="Enable CDK debug mode",
    )
    parser.add_argument(
        "--cdk-cmd",
        type=str,
        choices=[
            "deploy",
            "create",
            "update",
            "ls",
            "list",
            "synth",
            "synthesize",
            "destroy",
            "bootstrap",
        ],
        default="deploy",
    )
    parser.add_argument(
        "--skip-config-message",
        action="store_const",
        const=True,
        default=False,
        help="Skip default_config message",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["json"],
        help="Output CfnOutputs via a text file",
    )

    args = parser.parse_args()

    # Use script location as current working directory
    install_directory = os.path.dirname(os.path.realpath(__file__))
    build_lambda_dependency(install_directory)
    os.chdir(install_directory)

    # Append Solution ID to Boto3 Construct
    aws_solution_user_agent = {"user_agent_extra": "AwsSolution/SO0072/2.7.5"}
    boto_extra_config = config.Config(**aws_solution_user_agent)

    splash_info = f"""
            [red]_____[bright_blue] ____  [magenta]______[yellow]___
           [red]/ ___/[bright_blue]/ __ \\\\[magenta]/ ____[yellow]/   |
           [red]\\__ \\\\[bright_blue]/ / / [magenta]/ /   [yellow]/ /| |
          [red]___/[bright_blue] / /_/ [magenta]/ /___[yellow]/ ___ |
         [red]/____/[bright_blue]\\____/[magenta]\\____[yellow]/_/  |_|
        [red]Scale-[bright_blue]Out [magenta]Computing on [yellow]AWS[default]
    ================================
    > Documentation: https://awslabs.github.io/scale-out-computing-on-aws/
    > Source Code: https://github.com/awslabs/scale-out-computing-on-aws/
    """

    print(splash_info)

    install_phases = {
        1: "Please provide a cluster name ('soca-' is automatically added as a prefix)",
        2: "Enter the name of an S3 bucket you own",
        3: "Please enter the username for your first LDAP account. This account will have admin privileges",
        4: "Please enter the password of your first LDAP account",
        5: "Choose the default operating system (this can be changed later for the compute nodes)",
        6: "Choose the SSH keypair to use",
        7: "Do you want to create a new VPC (default) or use an existing one?",
        8: "Do you want to create new security groups (default) or use existing ones? ",
        9: "Do you want to create new filesystems for /apps & /data (default) or use existing ones? ",
        10: "Do you want to create a new Directory Service Managed AD (default) or use an existing one? ",
        11: "Do you want to create a new Analytics back-end (OpenSearch) (default) or use an existing one?",
        12: "Do you want to create new IAM roles for scheduler & compute nodes (default) or use existing ones?",
    }
    total_install_phases = len(install_phases)
    install_parameters = {
        # SOCA parameters
        "base_os": None,
        "account_id": None,
        "bucket": None,
        "ldap_user": None,
        "ldap_password": None,
        "ssh_keypair": None,
        "cluster_name": None,
        "cluster_id": None,
        "custom_ami": None,
        "region": None,
        "client_ip": None,
        # Network
        "vpc_id": None,
        "vpc_azs": None,
        "public_subnets": None,
        "private_subnets": None,
        # Filesystem for /data and /apps
        "fs_apps_provider": None,
        "fs_apps": None,
        "fs_data_provider": None,
        "fs_data": None,
        # AWS Directory Service Managed AD
        "directory_service_user": None,
        "directory_service_user_password": None,
        "directory_service_shortname": None,
        "directory_service_name": None,
        "directory_service_id": None,
        "directory_service_dns": None,
        # EC2 Security Groups
        "compute_node_sg": None,
        "scheduler_sg": None,
        # IAM role
        "compute_node_role_name": None,
        "compute_node_role_arn": None,
        "computenode_role_from_previous_soca_deployment": None,
        "scheduler_role_name": None,
        "scheduler_role_arn": None,
        "scheduler_role_from_previous_soca_deployment": None,
        "spotfleet_role_name": None,
        "spotfleet_role_arn": None,
        "spotfleet_role_from_previous_soca_deployment": None,
        # ElasticSearch
        "es_domain": None,
    }
    print("\n====== Validating Default SOCA Configuration ======\n")

    install_properties = get_install_properties(pathname=args.config)
    if args.override:
        overrides: list = [item for sublist in args.override for item in sublist]
        install_properties = override_keys(overrides, install_properties)
    install_parameters["install_properties"] = base64.b64encode(
        json.dumps(install_properties).encode("utf-8")
    ).decode("utf-8")

    install_props = json.loads(
        json.dumps(install_properties),
        object_hook=lambda d: SimpleNamespace(**d),
    )

    if not args.skip_config_message:
        if (
            get_input(
                f"SOCA will create AWS resources using the default parameters specified on installer/default_config.yml. \n Make sure you have read, reviewed and updated them (if needed). Enter 'yes' to continue ...",
                None,
                ["yes", "no"],
                str,
            )
            != "yes"
        ):
            sys.exit(1)

    print("\n====== Validating AWS Environment ======\n")
    # Load AWS custom profile if specified
    if args.profile:
        try:
            session = boto3.session.Session(profile_name=args.profile)
        except ProfileNotFound:
            print(
                f"[red] Profile {args.profile} not found. Check ~/.aws/credentials file"
            )
            sys.exit(1)
    else:
        session = boto3.session.Session()

    # Determine all AWS regions available on the account. We do not display opt-out regions
    # This uses us-east-1 as a default probe destination
    # For alternate partitions (e.g. GovCloud) - the AWS_DEFAULT_REGION should be set prior
    # to running the installer else we will not be able to enumerate the regions in the partition.
    default_region = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    ec2 = session.client("ec2", region_name=default_region, config=boto_extra_config)
    try:
        # describe_regions does not support pagination 12 Dec 2023
        accepted_regions = [
            region["RegionName"] for region in ec2.describe_regions()["Regions"]
        ]
    except ClientError as err:
        print(
            f"[yellow]Unable to list all AWS regions, you will need to enter it manually or give ec2:Describe* IAM permission. {err} "
        )
        accepted_regions = []

    # Build a dict of the accepted_regions

    accepted_regions_dict: dict = defaultdict(dict)

    for _region in accepted_regions:

        if _region == default_region:
            accepted_regions_dict[_region]['default'] = True
            accepted_regions_dict[_region]['visible'] = True
        else:
            accepted_regions_dict[_region]['default'] = False
            accepted_regions_dict[_region]['visible'] = True

    # Choose region where to install SOCA
    install_parameters["region"] = get_input(
        prompt="What AWS region do you want to install SOCA?",
        specified_value=args.region,
        expected_answers=accepted_regions_dict,
        expected_type=str,
    )

    # Initiate boto3 clients now the region is known
    # TODO - there are better ways to do this
    ec2 = session.client(
        "ec2", region_name=install_parameters["region"], config=boto_extra_config
    )
    sts = session.client(
        "sts", region_name=install_parameters["region"], config=boto_extra_config
    )
    s3 = session.resource(
        "s3", region_name=install_parameters["region"], config=boto_extra_config
    )
    efs = session.client(
        "efs", region_name=install_parameters["region"], config=boto_extra_config
    )
    fsx = session.client(
        "fsx", region_name=install_parameters["region"], config=boto_extra_config
    )

    cloudformation = session.client(
        "cloudformation",
        region_name=install_parameters["region"],
        config=boto_extra_config,
    )
    iam = session.client(
        "iam", region_name=install_parameters["region"], config=boto_extra_config
    )
    accepted_aws_values = accepted_aws_resources(region=install_parameters["region"])

    # Verify if we have the default Service Linked Role for ElasticSearch. SOCA will create it if needed
    try:
        es_roles = iam.list_roles(PathPrefix="/aws-service-role/es.amazonaws.com")
        if len(es_roles["Roles"]) == 0:
            install_parameters["create_es_service_role"] = True
        else:
            install_parameters["create_es_service_role"] = False
    except ClientError as err:
        print(
            f"[red]Unable to determine if you have a ServiceLinked created on your account for ElasticSearch. Verify your IAM permissions: {err} "
        )
        sys.exit(1)

    # Retrieve the AWS Account ID for CDK
    try:
        install_parameters["account_id"] = sts.get_caller_identity()["Account"]
    except Exception as err:
        print(f"[red] Unable to retrieve the Account ID due to {err}")
        sys.exit(1)

    # Automatically detect client ip if needed
    if not args.client_ip:
        install_parameters["client_ip"] = detect_customer_ip()
        print(
            f"[yellow]We determined your IP is {install_parameters['client_ip']}. You can change it later if you are running behind a proxy"
        )
        if install_parameters["client_ip"] is False:
            install_parameters["client_ip"] = get_input(
                "Client IP authorized to access SOCA on port 443/22",
                args.client_ip,
                None,
                str,
            )
    else:
        install_parameters["client_ip"] = args.client_ip

    if install_parameters["client_ip"].endswith("/32"):
        pass
    else:
        if "/" not in install_parameters["client_ip"]:
            print(
                f"[yellow]No subnet defined for your IP. Adding /32 at the end of {install_parameters['client_ip']}"
            )
            client_ip = f"{install_parameters['client_ip']}/32"

    # Get SOCA parameters
    get_install_parameters()

    # Validate Config, relaunch installer if needed
    while validate_soca_config(install_parameters, install_props) is False:
        get_install_parameters()

    # Validate CloudFormation stack name
    try:
        check_if_name_exist = cloudformation.describe_stacks(
            StackName=install_parameters["cluster_id"]
        )
        if len(check_if_name_exist["Stacks"]) != 0:
            if args.cdk_cmd == "create":
                print(
                    f"[red]Error. {install_parameters['cluster_id']} already exists in CloudFormation. Please pick a different name (soca- is automatically added as a prefix)."
                )
                sys.exit(1)
            elif args.cdk_cmd == "deploy":
                print(
                    f"[red]Error. {install_parameters['cluster_id']} already exists in CloudFormation. Use --cdk-cmd update if you want to update it."
                )
                sys.exit(1)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ValidationError":
            if args.cdk_cmd == "update":
                print(
                    f"[red]Error. {install_parameters['cluster_id']} does not exist in CloudFormation so can't be updated. Use --cdk-cmd deploy if you want to create it."
                )
                sys.exit(1)
            else:
                # Stack does not exist so create it
                pass
        else:
            print(
                f"[red]Error checking if {install_parameters['cluster_id']} already exists in CloudFormation due to {e}."
            )
            sys.exit(1)

    # Prepare CDK commands
    if args.cdk_cmd in ["create", "update"]:
        cdk_cmd = "deploy"
    else:
        cdk_cmd = args.cdk_cmd
    cmd = f"cdk {cdk_cmd} -c {' -c '.join('{}={}'.format(key,val) for (key,val) in install_parameters.items() if val is not None)} --require-approval never"
    cmd_bootstrap = f"cdk bootstrap aws://{install_parameters['account_id']}/{install_parameters['region']} -c {' -c '.join('{}={}'.format(key,val) for (key,val) in install_parameters.items() if val is not None)}"

    if args.debug:
        cmd += " --debug -v -v -v"

    if args.profile:
        cmd += f" --profile {args.profile}"
        cmd_bootstrap += f" --profile {args.profile}"

    # Adding --debug flag will output the cdk deploy command. This is helpful for troubleshooting.
    # Be careful as --ldap-password will be shown in plain text
    if args.debug:
        print(f"\nExecuting {cmd}")

    # Log command in history book
    with open("installer_history.txt", "a+") as f:
        f.write(
            f"""\n==== [{datetime.datetime.utcnow()}] ====
{cmd.replace(install_parameters['ldap_password'], '<REDACTED_PASSWORD>')}
{str(install_parameters).replace(install_parameters['ldap_password'], '<REDACTED_PASSWORD>')}
============================="""
        )

    # First, Bootstrap the environment. This will create a staging S3 bucket if needed
    print("\n====== Running CDK Bootstrap ======\n")

    bootstrap_environment = os.system(cmd_bootstrap)  # nosec
    if int(bootstrap_environment) != 0:
        print(
            f"[red] Error! Unable to bootstrap environment. Please run {cmd_bootstrap} and fix any errors"
        )
        print(f"[red] Error: {bootstrap_environment} ")
        sys.exit(1)

    # Upload required assets to customer S3 account
    if cdk_cmd == "deploy":
        upload_objects(
            install_directory,
            install_parameters["bucket"],
            install_parameters["cluster_id"],
        )

    # Then launch the actual SOCA installer
    print("\n====== Deploying SOCA ======\n")
    launch_installer = os.system(cmd)  # nosec

    if cdk_cmd == "deploy":
        if int(launch_installer) == 0:
            # SOCA is installed. We will now wait until SOCA is fully configured (when the ELB returns HTTP 200)
            print(f"[green]SOCA was installed successfully!")
            try:
                check_cfn = cloudformation.describe_stacks(
                    StackName=install_parameters["cluster_id"]
                )
                if args.format == "json":
                    with open(
                        f"{install_parameters['cluster_id']}.output", "w"
                    ) as outfile:
                        json.dump(check_cfn["Stacks"][0]["Outputs"], outfile)

                for output in check_cfn["Stacks"][0]["Outputs"]:
                    if output["OutputKey"] == "WebUserInterface":
                        print(
                            f"SOCA Web Endpoint is {output['OutputValue']} . Now checking if SOCA is fully configured (this could take up to 30 minutes)"
                        )
                        # Run a first check to determine if client IP provided by the customer is valid
                        try:
                            check_firewall = get(
                                f"{output['OutputValue']}", verify=False, timeout=35
                            )  # nosec
                        except Timeout:
                            print(
                                f"[yellow]Unable to connect to the SOCA endpoint URL. Maybe your IP {install_parameters['client_ip']} is not valid/has changed (maybe you are behind a proxy?). If that's the case please go to AWS console and authorize your real IP on the Scheduler Security Group"
                            )
                            sys.exit(1)
                        except ConnectionError as e:
                            print(
                                f"[yellow]WARNING - Encountered ConnectionError. Unable to connect to the SOCA endpoint URL. Error: {e} "
                            )
                        except ConnectionRefusedError as e:
                            print(
                                f"[yellow]WARNING - Encountered ConnectionRefusedError. Unable to connect to the SOCA endpoint URL. Error: {e} "
                            )

                        soca_check_loop = 0
                        if install_parameters["vpc_id"]:
                            # SOCA deployment is shorter when using existing resources, so we increase the timeout
                            max_check_loop = 30
                        else:
                            max_check_loop = 20
                        # print(f"DEBUG - Starting Endpoint check loop - MaxCheckLoop: {max_check_loop}")
                        while (
                            get(
                                output["OutputValue"], verify=False, timeout=15
                            ).status_code
                            != 200
                            and soca_check_loop <= max_check_loop
                        ):  # nosec
                            print(
                                "SOCA not ready yet, checking again in 120 seconds ... "
                            )
                            time.sleep(120)
                            soca_check_loop += 1
                            if soca_check_loop >= max_check_loop:
                                print(
                                    f"[yellow]Could not determine if SOCA is ready after {max_check_loop*2} minutes. Connect to the system via SSM and check the logs. "
                                )
                                sys.exit(1)

                        print(
                            f"[green]SOCA is ready! Login via  {output['OutputValue']}"
                        )

            except ValidationError:
                print(
                    f"{install_parameters['cluster_id']} is not a valid cloudformation stack"
                )
            except ClientError as err:
                print(
                    f"Unable to retrieve {install_parameters['cluster_id']} stack outputs, probably due to a permission error (your IAM account do not have permission to run cloudformation:Describe*. Log in to AWS console to view your stack connection endpoints"
                )

    elif args.cdk_cmd == "destroy":
        # Destroy stack if known
        cmd_destroy = f"cdk destroy {install_parameters['cluster_id']} -c {' -c '.join('{}={}'.format(key, val) for (key, val) in install_parameters.items() if val is not None)} --require-approval never"
        print(f"Deleting stack, running {cmd_destroy}")
        delete_stack = os.system(cmd_destroy)  # nosec
    else:
        # synth, ls etc ..
        pass
