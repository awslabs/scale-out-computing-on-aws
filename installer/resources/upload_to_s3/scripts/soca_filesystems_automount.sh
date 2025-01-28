#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script retrieve the /configuration/FileSystems tree for your SOCA environment and mount relevant partitions
# This script is downloaded from:
#  - s3://<bucket_specified_at_install_time>/<soca_cluster_name>/config/do_not_delete/scripts/soca_filesystems_automount.sh
#

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: Log Functions. Added via common.j2
function log_debug() {
  log_wrapper "DEBUG" "${@}"
}

function log_info() {
  log_wrapper "INFO" "${@}"
}

function log_warning() {
  log_wrapper "WARNING" "${@}"
}

function log_error() {
  log_wrapper "ERROR" "${@}"
}

function exit_fail () {
  log_wrapper "FATAL" "${@}"
  exit 1
}

function log_wrapper() {
  # To avoid issue with native echo and log_info in function (both write to stdout), we are redirecting log_info to stderr
  # we use echo to return function output from specific functions
  local LOG_LEVEL="$1"
  shift
  local VALID_LOG_LEVELS=("INFO" "DEBUG" "WARNING" "ERROR" "FATAL")
  if [[ ! "${VALID_LOG_LEVELS[*]}" =~ "${LOG_LEVEL}" ]]; then
    echo "[$(date +"%Y-%m-%d %H:%M:%S,%3N")] [INVALID] Invalid log level: ${LOG_LEVEL}, Call log_debug log_info log_warning log_error or exit_fail directly." >&2
    exit 1
  fi

  local LOG_MESSAGE="[$(date +"%Y-%m-%d %H:%M:%S,%3N")] [${LOG_LEVEL}] ${@}"
  if [[ -n "${SOCA_BOOTSTRAP_LOGS_FOLDER}" ]] && [[ -d "${SOCA_BOOTSTRAP_LOGS_FOLDER}" ]]; then
    # Keep track of warning/fatal/error on stdout as well as separate files
    if [[ ${LOG_LEVEL} == "WARNING" ]] || [[ ${LOG_LEVEL} == "FATAL" ]] || [[ ${LOG_LEVEL} == "ERROR" ]]; then
      echo "${LOG_MESSAGE}" | tee -a "${SOCA_BOOTSTRAP_LOGS_FOLDER}/bootstrap_${LOG_LEVEL}.log" >&2
    else
      echo "${LOG_MESSAGE}" >&2
    fi
  else
    # Handle case where SOCA_BOOTSTRAP_LOGS_FOLDER is not set
    echo "${LOG_MESSAGE}" >&2
  fi
}
# End: Log Functions

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: File Downloader (HTTP and S3) Added via common.j2
function file_download() {

  # file_download --download-url="https://link/file.txt" --save-as="file.txt" <-- will download from internet via https
  # file_download --download-url="s3://mybucket/file.txt" --save-as="file.txt"  <-- will download from s3 via awscli
  # Optional: Specify --sha256-checksum to verify data integrity
  # Optional: Specify --wget-options to add any addition options (note: --quiet is enabled by default)

  local DOWNLOAD_URL
  local SAVE_AS
  local SHA256_CHECKSUM_EXPECTED
  local SHA256_CHECKSUM_FOUND
  local WGET_OPTIONS
  local DOWNLOAD_TYPE
  log_info "Detected file_download request with args: ${*}"

  for arg in "$@"; do
    case $arg in
      --download-url=*) DOWNLOAD_URL="${arg#*=}" ;;
      --save-as=*) SAVE_AS="${arg#*=}" ;;
      --sha256-checksum=*) SHA256_CHECKSUM_EXPECTED="${arg#*=}" ;;
      --wget-options=*) WGET_OPTIONS="${arg#*=}" ;;
      *) exit_fail "Unknown arg ${arg} for file_download";;
    esac
  done

  if [[ ${DOWNLOAD_URL} =~ ^s3://$ ]]; then
      log_info "${DOWNLOAD_URL} seems to be a S3 URL, setting DOWNLOAD_TYPE to S3"
      DOWNLOAD_TYPE="s3"
  else
       log_info "${DOWNLOAD_URL} seems to be an HTTP URL, setting DOWNLOAD_TYPE to http"
      DOWNLOAD_TYPE="http"
  fi

  if [[ -z ${DOWNLOAD_URL} ]]; then
    exit_fail "DOWNLOAD_URL not found for file_download. Please specify --download-url"
  fi

  if [[ -z ${DOWNLOAD_TYPE} ]]; then
    log_info "DOWNLOAD_TYPE not found, default to HTTP. Specify --download-type http or s3. "
    DOWNLOAD_TYPE="http"
  fi

  if [[ ! ${DOWNLOAD_TYPE} == "s3" ]] && [[ ! ${DOWNLOAD_TYPE} == "http" ]]; then
    exit_fail "DOWNLOAD_TYPE must be either s3 or http. Detected ${DOWNLOAD_TYPE} . Specify --download-type http or s3. "
  fi


  if [[ -z ${SAVE_AS} ]]; then
    exit_fail "SAVE_AS not found, for file_download. Please specify --save-as"
  fi

  if [[ ${DOWNLOAD_TYPE} == "http" ]]; then
    # HTTP
    if ! verify_package_installed wget; then
      packages_install wget
    fi

    # note: Do not add WGET_OPTIONS between quotes to avoid them being treated as string
    if wget --quiet ${WGET_OPTIONS} "${DOWNLOAD_URL}" -O "${SAVE_AS}"; then
      log_info "${DOWNLOAD_URL} downloaded successfully and saved as ${SAVE_AS}"
    else
      exit_fail "Error downloading [${DOWNLOAD_URL}] wget returned an error, check the logs for more details"
    fi

  else
    # S3
    if aws_cli s3 cp ${DOWNLOAD_URL} ${SAVE_AS} --quiet; then
      log_info "${DOWNLOAD_URL} downloaded successfully and saved as ${SAVE_AS}"
    else
      exit_fail "Error downloading ${DOWNLOAD_URL}. aws_cli returned an error"
    fi
  fi

  # If --sha256-checksum is provided, proceed to an integrity check
  if [[ -n ${SHA256_CHECKSUM_EXPECTED} ]]; then
    log_info "--sha256-checksum found, verifying file"
    SHA256_CHECKSUM_FOUND=$(sha256sum "${SAVE_AS}" | awk '{print $1}')
    if [[ "${SHA256_CHECKSUM_FOUND}" != "${SHA256_CHECKSUM_EXPECTED}" ]];  then
      exit_fail "Checksum for ${DOWNLOAD_URL} failed. Expected SHA256 ${SHA256_CHECKSUM_EXPECTED}, but found ${SHA256_CHECKSUM_FOUND} File may be compromised."
    else
      log_info "Checksum verified: Expected SHA256 ${SHA256_CHECKSUM_EXPECTED}, found ${SHA256_CHECKSUM_FOUND}"
    fi
  fi
}
# End: File Downloader

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# These functions are available on all services (controller, compute node, login node, scheduler ...) via `common.sh.j2`
# Always use theses function when interacting with system packages.

function packages_remove () {
  # Remove specified packages (e.g: packages_remove pkg1 pkg2 ... pkgN)
  if [[ $# -eq 0 ]]; then
    exit_fail "packages_remove - No package list specified. Exiting... "
  fi

  
    packages_exec_command dnf remove -y "${@}"
  
}

function packages_install () {
  # Install specified packages (e.g: packages_install pkg1 pkg2 ... pkgN)
  if [[ $# -eq 0 ]]; then
    exit_fail "packages_install - No package list specified. Exiting... "
  fi

  
    packages_exec_command dnf install -y "${@}"
  
}

function verify_package_installed () {
  # Return "true" is a given package is installed (e.g: verify_package_installed pkg_name)
  if [[ $# -eq 0 ]]; then
    exit_fail "verify_package_installed - No package list specified. Exiting... "
  fi

  
    rpm -q ${1} &> /dev/null &&  return 0 || return 1
  
}

function packages_clean () {
  # Remove un-necessary packages
  
    packages_exec_command dnf clean all
  
}

function packages_generic_command() {
  # generic wrapper for commands other than install/remove
  
    packages_exec_command dnf "${@}"
  
}

function packages_exec_command () {
  # wrapper for all exec commands
  local MAX_ATTEMPTS=10
  local ATTEMPT_NUMBER=1
  local SLEEP_TIME_SECONDS=60
  local EXEC_COMMAND=("$@")
  log_info "Attempting to run ${EXEC_COMMAND[@]}"
  while [[ ${ATTEMPT_NUMBER} -le ${MAX_ATTEMPTS} ]]; do
    log_info "Attempt ${ATTEMPT_NUMBER}/${MAX_ATTEMPTS})"
    "${EXEC_COMMAND[@]}"
    if [[ $? -eq 0 ]]; then
      log_info "Command successful after: ${ATTEMPT_NUMBER}/${MAX_ATTEMPTS} attempts"
      return 0
    else
      log_error "${EXEC_COMMAND[@]} failed on Attempt ${ATTEMPT_NUMBER}/${MAX_ATTEMPTS}. Will try again in ${SLEEP_TIME_SECONDS} seconds"
      sleep ${SLEEP_TIME_SECONDS}
      ((ATTEMPT_NUMBER++))
    fi
  done
  exit_fail "${EXEC_COMMAND[@]} failed after all attempts, exiting .."
}

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: Reboot management. Added via common.sh.j2
function unset_reboot_required () {
  echo -n "no" > /root/.soca_reboot_required.txt
}

function set_reboot_required () {
  log_info "[REBOOT REQUIRED]: ${1}"
  echo -n "yes" > /root/.soca_reboot_required.txt
}

function get_reboot_required () {
  if [[ -f /root/.soca_reboot_required.txt ]]; then
    cat /root/.soca_reboot_required.txt
  else
     echo -n "no"
  fi
}
# End: Reboot Management

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin - Wrapper AWSCLI. Added via common.sh.j2
function aws_cli () {
  local AWS=$(command -v aws)

  # Will verify if the output of the command to run is on the cache
  local CHECK_CACHE="true"
  local CACHED_RESULT

  # Automatically add --region if not specified
  if [[ "$*" == *"--region"* ]]; then
    local AWS_API_CALL="${AWS} $*"
  else
    local AWS_API_CALL="${AWS} --region us-east-2 $*"
  fi

  # Do not check cache_get_key for any query specific to secretsmanager as cache_get_key has a dependency with aws_cli
  # and will cause circular dependency errors. Moreover, secrets must not be cached on ElastiCache.
  if [[ "$*" == "secretsmanager"* ]]; then
    CHECK_CACHE="false"
  fi

  # Check if this API call has already been executed previously and results are available on ElastiCache
  if [[ "${CHECK_CACHE}" == "true" ]]; then
    # cache_get_key is not available on User Data and imported via cache_client.sh.j2
    if declare -F cache_get_key > /dev/null; then
      CACHED_RESULT=$(cache_get_key "${AWS_API_CALL}")
      if [[ ${CACHED_RESULT} == "CACHE_MISS" ]]; then
        # Key does not exist on ElastiCache, run actual API call
        ${AWS_API_CALL}
      else
        echo -n ${CACHED_RESULT}
      fi
    else
      # cache_get_key function does not exist, import it via cache_client.sh.j2, default actual API call.
      ${AWS_API_CALL}
    fi
  else
    # bypass cache, run actual API call
    ${AWS_API_CALL}
  fi

}
# End - Wrapper AWSCLI

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin - Wrapper EC2. Added via common.sh.j2
function ec2_describe_instance_types () {
  # Wrapper for ec2 describe-instance-types
  # ex:
  # describe_instance_types "GpuInfo.Gpus[].Manufacturer"
  # describe_instance_types "InstanceType"

  local PARAMETER="${1}"
  local INSTANCE_INFO
  local CACHED_RESULT
  local INSTANCE_TYPE=$(instance_type)

  if [[ -z ${PARAMETER} ]]; then
    local JQ_QUERY=".InstanceTypes[]"
  else
    local JQ_QUERY=".InstanceTypes[].${PARAMETER}"
  fi

  INSTANCE_INFO=$(aws_cli ec2 describe-instance-types --instance-types "${INSTANCE_TYPE}" --output json)
  echo -n ${INSTANCE_INFO} | jq -r "${JQ_QUERY}  // empty" 2>/dev/null || echo -n ""
}
# End - Wrapper EC2

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin - Wrapper IMDS. Added via common.sh.j2
function imds_get () {
  local SLASH=''
  local IMDS_HOST="http://169.254.169.254"
  local IMDS_TTL="300"
  # prepend a slash if needed
  if [[ "${1:0:1}" == '/' ]]; then
    SLASH=''
  else
    SLASH='/'
  fi
  local URL="${IMDS_HOST}${SLASH}${1}"

  # Get an Auth token
  local TOKEN=$(curl --silent -X PUT "${IMDS_HOST}/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: ${IMDS_TTL}")

  # Get the requested value and echo it back
  local OUTPUT=$(curl --silent -H "X-aws-ec2-metadata-token: ${TOKEN}" "${URL}")
  echo -n "${OUTPUT}"
}

function instance_type () {
  echo -n $(imds_get /latest/meta-data/instance-type)
}

function instance_family () {
  echo -n  $(imds_get /latest/meta-data/instance-type | cut -d. -f1)
}

function instance_id () {
  echo -n $(imds_get /latest/meta-data/instance-id)
}

function instance_region () {
  echo -n $(imds_get /latest/meta-data/placement/region)
}

function instance_az () {
  echo -n $(imds_get /latest/meta-data/placement/availability-zone)
}
# End - Wrapper IMDS

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin - Wrapper for Secrets Manager. Added via common.sh.j2
function get_secret() {
    local SECRET_NAME="${1}"
    local MAX_ATTEMPT=10
    local CURRENT_ATTEMPT=0
    local SLEEP_INTERVAL=180

    if ! verify_package_installed jq; then
      packages_install jq
    fi

    local JQ=$(which jq)
    while ! secret=$(aws_cli secretsmanager get-secret-value --secret-id "${SECRET_NAME}" --query SecretString --output json); do
        ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
        if [[ ${CURRENT_ATTEMPT} -ge ${MAX_ATTEMPT} ]]; then
            exit_fail "error: Timed out waiting for secret ${SECRET_NAME} from secrets manager"
        fi
        log_info "Secret Manager is not ready yet for ${SECRET_NAME} ... Waiting ${SLEEP_INTERVAL} s... Loop count is: ${CURRENT_ATTEMPT}/${MAX_ATTEMPT}"
        sleep ${SLEEP_INTERVAL}
    done
    echo -n ${secret}
}
# End - Wrapper for Secrets Manager

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin - Setup /etc/environment
function set_environment_variable () {
  local VARIABLE_NAME=${1}
  local VARIABLE_VALUE=${2}
  local SOCA_LINE_SUFFIX_IDENTIFIER="# SOCA Environment Variable, [SOCA_DO_NOT_DELETE]" # added to each entry

  if [[ -z ${VARIABLE_NAME} ]]; then
    exit_fail "set_environment_variable. VARIABLE_NAME (first argument) not found"
  fi
  if [[ -z ${VARIABLE_VALUE} ]]; then
    exit_fail "set_environment_variable. VARIABLE_VALUE (second argument) not found"
  fi
  log_info "Setting ${VARIABLE_NAME}=${VARIABLE_VALUE} to /etc/environment"
  if grep -q "^[^#]*${VARIABLE_NAME}=${VARIABLE_VALUE}" /etc/environment; then
      log_info "${VARIABLE_NAME}=${VARIABLE_VALUE} already found in  /etc/environment, ignoring ..."
  else
      if grep -q "^[^#]*${VARIABLE_NAME}=" /etc/environment; then
        log_info "${VARIABLE_NAME}= found but not pointing to ${VARIABLE_VALUE}, remove the line ... "
        sed -i "/^[^#]*${VARIABLE_NAME}=/d" /etc/environment
      fi
      log_info "Adding ${VARIABLE_NAME}=${VARIABLE_VALUE} to /etc/environment"
      {
        echo export "${VARIABLE_NAME}=\"${VARIABLE_VALUE}\"" ${SOCA_LINE_SUFFIX_IDENTIFIER}
      } >> /etc/environment
      # Export for current shell
      export "${VARIABLE_NAME}=${VARIABLE_VALUE}"
  fi
}
# End - Setup /etc/environment


export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/pbs/bin:/opt/pbs/sbin:/apps/soca/soca-rhel12:${PATH}

# Source environment
source /etc/environment

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: EFS mount

  

  # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


  

  function fstab_wrapper () {
    # $1 = <file system> <mount point> <type> <options> <dump> <pass>
    # filesystem: The device/partition (by /dev location or UUID) that contain a file system.
    # mount point: The directory on your root file system (aka mount point) from which it will be possible to access the content of the device/partition. Mount points should not have spaces in the names.
    # type: Type of file system (ext4, nfs4, lustre ..)
    # options: Mount options of access to the device/partition
    # dump: Enable or disable backing up of the device/partition. Default to 0 (Disable) it if not specified
    # pass: Controls the order in which fsck checks the device/partition for errors at boot time. The root device should be 1. Other partitions should be 2, or 0 to disable checking. Default to 0 if not set
    # eg: 10.1.1.6:/   /mypath          nfs4    defaults   0       0

    # Note: Return 0 for successful mount or 1 for error

    local FSTAB_ENTRY=(${1})
    local MOUNT_FILESYSTEM=${FSTAB_ENTRY[0]}
    local MOUNT_POINT=${FSTAB_ENTRY[1]}
    local MOUNT_TYPE=${FSTAB_ENTRY[2]}
    local MOUNT_OPTIONS=${FSTAB_ENTRY[3]}
    local MOUNT_DUMP=${FSTAB_ENTRY[4]-"0"}
    local MOUNT_PASS=${FSTAB_ENTRY[5]-"0"}

    local MOUNT_VERIFICATION
    local MOUNT_ATTEMPT

    log_info "Received new fstab entry request: ${FSTAB_ENTRY}"

    if [[ -z "${MOUNT_FILESYSTEM}" ]] || [[ -z "${MOUNT_POINT}" ]] || [[ -z "${MOUNT_TYPE}" ]] || [[ -z "${MOUNT_OPTIONS}" ]]; then
      log_error "Invalid entry. Expected <filesystem> <mount_point> <mount_type> <options> [[<dump> <pass>]], received ${FSTAB_ENTRY}"
      return 1
    fi

    if grep -qF "${MOUNT_FILESYSTEM} ${MOUNT_POINT}" /etc/fstab; then
      log_info "This entry seems to already exist on /etc/fstab"
      return 0
    fi

    if mount | grep -q "${MOUNT_POINT}"; then
      if mount | grep "${MOUNT_POINT}" | grep -q ${MOUNT_FILESYSTEM} ; then
        log_info "${MOUNT_POINT} is already mounted"
        return 0
      else
        log_error "${MOUNT_POINT} is mounted to a different disk"
        return 1
      fi
    fi

    # nslookup install
    if ! verify_package_installed bind-utils; then
      packages_install bind-utils
    fi

    # nfs-utils
    if ! verify_package_installed nfs-utils; then
      log_info "Installing nfs-utils"
      packages_install nfs-utils
    fi

    log_info "Creating ${MOUNT_POINT} if needed"
    mkdir -p ${MOUNT_POINT}

    # Adding to /etc/fstab
    log_info "Adding ${MOUNT_FILESYSTEM} ${MOUNT_POINT} ${MOUNT_TYPE} ${MOUNT_OPTIONS} ${MOUNT_DUMP} ${MOUNT_PASS} to /ec/fstab"
    echo "${MOUNT_FILESYSTEM} ${MOUNT_POINT} ${MOUNT_TYPE} ${MOUNT_OPTIONS} ${MOUNT_DUMP} ${MOUNT_PASS}" >> /etc/fstab

    # Trying to mount
    for ((MOUNT_ATTEMPT=1; MOUNT_ATTEMPT<=10; MOUNT_ATTEMPT++)); do
      log_info "Mounting attempt ${MOUNT_ATTEMPT}/10 ..."

      if mount ${MOUNT_POINT}; then
        log_info "mount ${MOUNT_POINT} command completed successfully"
        break
      fi

      local SLEEP_TIME=$(( RANDOM % 60 ))
      sleep ${SLEEP_TIME}
      if [[ "${MOUNT_ATTEMPT}" -eq 5 ]]; then
        log_error "Failed to mount ${MOUT_MOUNT_FILESYSTEM} after 10 attempts."
        return 1
      fi
    done
    return 0
  }


  function mount_efs () {
      # MOUNT_TARGET (required): EFS Filesystem ID. Used to determine actual mount endpoint if ENDPOINT is not set
      # MOUNT_PATH (required): Unix path to mount the EFS on
      # ON_MOUNT_FAILURE (required): What to do if the mount is not successful (exit or ignore)
      # MOUNT_OPTIONS (optional): NFS options to use
      # ENABLED (optional): Whether the automount is enabled

      local MOUNT_TARGET
      local MOUNT_PATH
      local MOUNT_OPTIONS
      local ON_MOUNT_FAILURE
      local ENABLED

      for arg in "$@"; do
          case $arg in
              --mount-target=*) MOUNT_TARGET="${arg#*=}" ;;
              --mount-path=*) MOUNT_PATH="${arg#*=}" ;;
              --mount-options=*) MOUNT_OPTIONS="${arg#*=}" ;;
              --on-mount-failure=*) ON_MOUNT_FAILURE="${arg#*=}" ;;
              --enabled=*) ENABLED="${arg#*=}" ;;
              *) exit_fail "Unknown arg ${arg} for mount_efs";;
          esac
      done

      if [[ -z "${ENABLED}" ]]; then
        ENABLED="true"
        log_warning "--enabled not set, default to ${ENABLED}"
      fi

      if [[ -z "${MOUNT_PATH}" ]]; then
        exit_fail "--mount-path not set for mount_efs"
      fi

      if [[ -z "${ON_MOUNT_FAILURE}" ]]; then
        ON_MOUNT_FAILURE="ignore"
        log_warning "--on-mount-failure not specified, default to ${ON_MOUNT_FAILURE}"
      fi

      if [[ -z ${MOUNT_OPTIONS} ]]; then
        MOUNT_OPTIONS="nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport"
        log_warning "--mount-options not set, default to ${MOUNT_OPTIONS}"
      fi

      if [[ "${ENABLED}" == "true" ]]; then

        # todo: efs-mount-helper
        # Retrieve the EFS mount target for the given AZ based on the EFS filesystem ID

        if [[ -z "${MOUNT_TARGET}" ]]; then
          exit_fail "--mount-target not set for mount_efs"
        else
          local EFS_ENDPOINT=$(aws_cli efs describe-mount-targets --file-system-id ${MOUNT_TARGET} --query "MountTargets[?AvailabilityZoneName=='$(instance_az)'].IpAddress" --output text)
          if [[ -z ${EFS_ENDPOINT} ]]; then
             exit_fail "Unable to find Mount Target for ${MOUNT_TARGET}"
          fi
          ENDPOINT="${EFS_ENDPOINT}:/"
        fi

        if fstab_wrapper "${ENDPOINT} ${MOUNT_PATH} nfs4 ${MOUNT_OPTIONS} 0 0"; then
          log_info "Successfully mounted ${ENDPOINT} as ${MOUNT_PATH}"
        else
          if [[ "${ON_MOUNT_FAILURE}" == "exit" ]]; then
            exit_fail "Unable to mount ${ENDPOINT} as ${MOUNT_PATH}"
          else
            log_warning "Unable to mount ${ENDPOINT} as ${MOUNT_PATH}, ignoring"
          fi
        fi

      else
        log_warning "EFS Filesystem ${MOUNT_TARGET}, mount path ${MOUNT_PATH} is not enabled. Skipping ... Detected enabled flag ${ENABLED}"
      fi
    }

# End: EFS mount

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: Mount FSx Lustre

  

  # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



  
    function rhel_driver_install {
      log_info "Installing FSx Lustre Driver for RHEL based distro"
      local EL_VERSION=${1}
      local REPO_VERSION_REWRITE=${2}

      if [[ ! ${EL_VERSION} =~ ^(7|8|9)$ ]]; then
        log_error "EL Version must be either 7, 8 or 9"
      else
        log_info "Getting FSx Lustre repo for RHEL distros version ${EL_VERSION}"

        file_download --download-url="https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-rpm-public-key.asc" --save-as="${SOCA_BOOTSTRAP_ASSETS_FOLDER}/fsx-rpm-public-key.asc"

        if [[ ! -f "/etc/yum.repos.d/aws-fsx.repo" ]]; then
          log_info "Downloading https://fsx-lustre-client-repo.s3.amazonaws.com/el/${EL_VERSION}/fsx-lustre-client.repo and saving it to /etc/yum.repos.d/aws-fsx.repo"
          file_download --download-url="https://fsx-lustre-client-repo.s3.amazonaws.com/el/"${EL_VERSION}"/fsx-lustre-client.repo" --save-as="/etc/yum.repos.d/aws-fsx.repo"
        fi

        if [[ -n "${REPO_VERSION_REWRITE}" ]]; then
          echo "SED Rewrite enabled ${REPO_VERSION_REWRITE}"
          sed -i "${REPO_VERSION_REWRITE}" /etc/yum.repos.d/aws-fsx.repo
        fi

        packages_clean
        if [[ ! -f "${SOCA_BOOTSTRAP_ASSETS_FOLDER}/fsx-rpm-public-key.asc" ]]; then
          log_warning "Unable to locate ${SOCA_BOOTSTRAP_ASSETS_FOLDER}/fsx-rpm-public-key.asc, installing without gpgcheck"
          packages_install kmod-lustre-client lustre-client --nogpgcheck
        else
          
            rpm --import "${SOCA_BOOTSTRAP_ASSETS_FOLDER}/fsx-rpm-public-key.asc"
          
          packages_install kmod-lustre-client lustre-client
        fi

      fi
      log_info "FSx Driver installed"
    }
  

  function mount_fsx_lustre {
    log_info "Preparing FSx Lustre mount"
    # MOUNT_TARGET (required): FSx for Lustre Filesystem ID. Used to determine actual mount endpoint if ENDPOINT is not set
    # MOUNT_PATH (required): Unix path to mount the EFS on
    # ON_MOUNT_FAILURE (required): What to do if the mount is not successful (exit or ignore)
    # MOUNT_OPTIONS (optional): NFS options to use
    # ENABLED (optional): Whether the automount is enabled

    for arg in "$@"; do
        case $arg in
            --mount-target=*) MOUNT_TARGET="${arg#*=}" ;;
            --mount-path=*) MOUNT_PATH="${arg#*=}" ;;
            --mount-options=*) MOUNT_OPTIONS="${arg#*=}" ;;
            --on-mount-failure=*) ON_MOUNT_FAILURE="${arg#*=}" ;;
            --enabled=*) ENABLED="${arg#*=}" ;;
            *) exit_fail "Unknown arg ${arg} for mount_efs";;
        esac
    done

    if [[ -z "${ENABLED}" ]]; then
      ENABLED="true"
      log_warning "--enabled not set, default to ${ENABLED}"
    fi

    if [[ -z "${MOUNT_PATH}" ]]; then
      exit_fail "--mount-path not set for mount_fsx_lustre"
    fi

    if [[ -z "${ON_MOUNT_FAILURE}" ]]; then
      ON_MOUNT_FAILURE="ignore"
      log_warning "--on-mount-failure not specified, default to ${ON_MOUNT_FAILURE}"
    fi

    if [[ -z "${MOUNT_OPTIONS}" ]]; then
      MOUNT_OPTIONS="defaults,noatime,flock,_netdev"
      log_warning "--mount-options not specified, default to ${ON_MOUNT_FAILURE}"
    fi

    if ! verify_package_installed jq; then
      log_info "jq not found, installing it ..."
      packages_install jq
    fi

    if [[ -z "${MOUNT_TARGET}" ]]; then
      exit_fail "--mount-target not set for mount_fsx_lustre"
    fi

    if [[ "${ENABLED}" == "true" ]]; then

      local FSX_LUSTRE_INFO=$(aws_cli fsx describe-file-systems --file-system-ids "${MOUNT_TARGET}")
      local FSX_LUSTRE_DNS=$(echo ${FSX_LUSTRE_INFO} | jq -r '.FileSystems[].DNSName // "NO_VALUE"')
      local FSX_LUSTRE_MOUNT_NAME=$(echo ${FSX_LUSTRE_INFO} | jq -r '.FileSystems[].LustreConfiguration.MountName // "NO_VALUE"')

      if [[ -z ${FSX_LUSTRE_DNS} ]]; then
        exit_fail "Unable to determine DNSName for ${MOUNT_TARGET}"
      fi

      if [[ -z ${FSX_LUSTRE_MOUNT_NAME} ]]; then
        exit_fail "Unable to determine MountName for ${MOUNT_TARGET}"
      fi

      local ENDPOINT="${FSX_LUSTRE_DNS}@tcp:/${FSX_LUSTRE_MOUNT_NAME}"
      local KERNEL=$(uname -r)
      local MACHINE=$(uname -m)

      for ((LIFECYCLE_VERIFICATION=1; LIFECYCLE_VERIFICATION<=30; LIFECYCLE_VERIFICATION++)); do
          log_info "Verifying if ${MOUNT_TARGET} is in AVAILABLE state ..."
          if [[ $(aws_cli fsx describe-file-systems --file-system-ids "${MOUNT_TARGET}" --query FileSystems[].Lifecycle --output text) == "AVAILABLE" ]]; then
            break
          else
            log_warning "FSx Lustre Not available yet .. trying again in 60 seconds, attempt ${LIFECYCLE_VERIFICATION}"
          fi
          if [[ ${LIFECYCLE_VERIFICATION} -eq 30 ]]; then
              exit_fail "Unable to determine if the filesystem is in AVAILABLE state after 30 attempts. Exiting."
          fi
          sleep 60
        done

      log_info "Preparing to install Lustre driver on kernel version: ${KERNEL} running on: ${MACHINE}"
      if ! verify_package_installed lustre-client; then
        # Install FSx for Lustre Client
        # https://docs.aws.amazon.com/fsx/latest/LustreGuide/install-lustre-client.html
        log_info "FSx Lustre Client not installed, installing it .. "
        
            case "$KERNEL$MACHINE" in
              *"5.14.0-503"*) rhel_driver_install 9 ;;
              *"5.14.0-427"*) rhel_driver_install 9 's#9#9.4#' ;;
              *"5.14.0-362"*) rhel_driver_install 9 's#9#9.3#' ;;
              *"5.14.0-70"*) rhel_driver_install 9 's#9#9.0#' ;;
              *) log_error "Can't install FSx for Lustre client as kernel version $KERNEL isn't matching expected versions for EL9";;
            esac
        
      else
        log_info "FSx Lustre Driver already installed ..."
      fi

      if fstab_wrapper "${ENDPOINT} ${MOUNT_PATH} lustre ${MOUNT_OPTIONS} 0 0"; then
        log_info "Successfully mounted ${ENDPOINT} as ${MOUNT_PATH}"
      else
        if [[ ${ON_MOUNT_FAILURE} == "exit" ]]; then
          exit_fail "Unable to mount ${ENDPOINT} as ${MOUNT_PATH}"
        else
          log_warning "Unable to mount ${ENDPOINT} as ${MOUNT_PATH}, ignoring"
        fi
      fi
    else
      log_warning "FSx Lustre Filesystem ${MOUNT_TARGET}, mount path ${MOUNT_PATH} is not enabled. Skipping ... Detected enabled flag ${ENABLED}"
    fi
    }

# End: Mount FSx Lustre

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: FSx OnTap


  

  # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



  function mount_fsx_ontap () {

    # MOUNT_TARGET (required): FSxN Volume ID. Used to determine actual mount endpoint if ENDPOINT is not set
    # MOUNT_PATH (required): Unix path to mount the the filesystem on
    # ON_MOUNT_FAILURE (required): What to do if the mount is not successful (exit or ignore)
    # MOUNT_OPTIONS (optional): NFS options to use
    # ENABLED (optional): Whether the automount is enabled

    local MOUNT_TARGET
    local MOUNT_PATH
    local MOUNT_OPTIONS
    local ON_MOUNT_FAILURE
    for arg in "$@"; do
        case $arg in
            --mount-target=*) MOUNT_TARGET="${arg#*=}" ;;
            --mount-path=*) MOUNT_PATH="${arg#*=}" ;;
            --mount-options=*) MOUNT_OPTIONS="${arg#*=}" ;;
            --on-mount-failure=*) ON_MOUNT_FAILURE="${arg#*=}" ;;
            --enabled=*) ENABLED="${arg#*=}" ;;
            *) exit_fail "Unknown arg ${arg} for mount_efs";;
        esac
    done

    if ! verify_package_installed jq; then
      log_info "jq not found, installing it ..."
      packages_install jq
    fi

    if [[ -z "${ENABLED}" ]]; then
      ENABLED="true"
      log_warning "--enabled not set, default to ${ENABLED}"
    fi

    if [[ -z "${MOUNT_PATH}" ]]; then
      exit_fail "--mount-path not set for mount_fsx_ontap"
    fi

    if [[ -z "${ON_MOUNT_FAILURE}" ]]; then
      ON_MOUNT_FAILURE="ignore"
      log_warning "--on-mount-failure not specified, default to ${ON_MOUNT_FAILURE}"
    fi

    if [[ -z "${MOUNT_TARGET}" ]]; then
      exit_fail "--mount-target not set for mount_fsx_ontap"
    fi

    if [[ -z "${MOUNT_OPTIONS}" ]]; then
      # Note: mounting via nfsv4 without idmapd configuration will cause group membership to break and default to nobody
      MOUNT_OPTIONS="defaults,noatime,_netdev"
      log_warning "--mount-options not set, default to ${MOUNT_OPTIONS}"
    fi

    if [[ "${ENABLED}" == "true" ]]; then
      # Retrieve FSx ONTAP Volume info
      local FSX_DESCRIBE_VOLUME=$(aws_cli fsx describe-volumes --volume-ids ${MOUNT_TARGET})
      local FSX_VOLUME_SVM_ID=$(echo ${FSX_DESCRIBE_VOLUME} | jq -r '.Volumes[].OntapConfiguration.StorageVirtualMachineId // "NO_VALUE"')
      local FSX_VOLUME_JUNCTION_PATH=$(echo ${FSX_DESCRIBE_VOLUME} | jq -r '.Volumes[].OntapConfiguration.JunctionPath // "NO_VALUE"')
      local FSX_VOLUME_RESOURCE_ARN=$(echo ${FSX_DESCRIBE_VOLUME} | jq -r '.Volumes[].ResourceARN // "NO_VALUE"')

      if [[ "${FSX_VOLUME_SVM_ID}" == "NO_VALUE" ]] || [[ "${FSX_VOLUME_JUNCTION_PATH}" == "NO_VALUE" ]] || [[ "${FSX_VOLUME_RESOURCE_ARN}" == "NO_VALUE" ]]; then
        exit_fail "Unable to verify required FSx Volume Information for ${MOUNT_TARGET} : FSX_VOLUME_RESOURCE_ARN = ${FSX_VOLUME_RESOURCE_ARN}, FSX_VOLUME_SVM_ID=${FSX_VOLUME_SVM_ID}, FSX_VOLUME_JUNCTION_PATH=${FSX_VOLUME_JUNCTION_PATH}. API Result ${FSX_DESCRIBE_VOLUME}"
      fi

      # Retrieve FSx ONTAP SVM info
      local FSX_DESCRIBE_SVM=$(aws_cli fsx describe-storage-virtual-machines --storage-virtual-machine-ids ${FSX_VOLUME_SVM_ID})
      if [[ ${FSX_VOLUME_SVM_ID} == "NO_VALUE" ]]; then
        exit_fail "Unable to determine SVM ID for FSX Volume ${MOUNT_TARGET}. API Result ${FSX_DESCRIBE_SVM}"
      else
        local NFS_DNS_NAME=$(echo ${FSX_DESCRIBE_SVM} | jq -r '.StorageVirtualMachines[].Endpoints.Nfs.DNSName // "NO_VALUE"' )
        if [[ ${NFS_DNS_NAME} == "NO_VALUE" ]]; then
          exit_fail "Unable to determine StorageVirtualMachines[].Endpoints.Nfs.DNSName for ${FSX_VOLUME_SVM_ID}. API Result ${FSX_DESCRIBE_SVM}"
        fi

        local DS_DOMAIN_NAME=$(echo ${FSX_DESCRIBE_SVM} | jq -r '.StorageVirtualMachines[0].ActiveDirectoryConfiguration.SelfManagedActiveDirectoryConfiguration.DomainName // "NO_VALUE"')
        if [[ ${DS_DOMAIN_NAME} == "NO_VALUE" ]]; then
          log_warning "Unable to determine AD Domain Name for ${FSX_VOLUME_SVM_ID}, group membership may default to nobody. API Result ${FSX_DESCRIBE_SVM}"
        else
           log_info "Updating idmap.conf to support correct AD group/user membership when using FSxN with nfs4"
            # Valid idmapd configuration is required when using NetApp otherwise group membership will be set to `nobody`
            # > https://kb.netapp.com/on-prem/ontap/da/NAS/NAS-KBs/NFSv4.x_mounts_show_file_and_group_owner_as_nobody
            cp /etc/idmapd.conf /etc/idmapd.conf.original.$(date +%s)
            log_info "Check if Domain=${DS_DOMAIN_NAME} exists in idmapd.conf"
            if grep -q "^[^#]*Domain=${DS_DOMAIN_NAME}" /etc/idmapd.conf; then
              log_info "Domain=${DS_DOMAIN_NAME} already found in idmapd.conf, ignoring ..."
            else
              if grep -q '^[^#]*Domain=' /etc/idmapd.conf; then
                log_info "Domain= found but not pointing to ${DS_DOMAIN_NAME}, remove the line ... "
                sed -i '/^[^#]*Domain=/d' /etc/idmapd.conf
              fi
              log_info "Adding Domain=${DS_DOMAIN_NAME} under the [General] section on /etc/idmapd.conf"
              sed -i "/^\[General\]/a Domain=${DS_DOMAIN_NAME}" /etc/idmapd.conf
              nfsidmap -c
            fi
        fi
        ENDPOINT="${NFS_DNS_NAME}:${FSX_VOLUME_JUNCTION_PATH}"
      fi

      if [[ "${SOCA_NODE_TYPE}" == "controller" ]]; then
       # Check if tag soca:OntapFirstSetup == true is there, only applicable on the controller
       # If yes, SOCA will proceed to initial CIFS/SVM configuration
        local FSX_VOLUME_TAG_ONTAP_FIRST_SETUP=$(aws_cli fsx list-tags-for-resource --resource-arn "${FSX_VOLUME_RESOURCE_ARN}" --query "Tags[?Key=='soca:OntapFirstSetup'].Value" --output text)
        if [[ "${FSX_VOLUME_TAG_ONTAP_FIRST_SETUP}" == "true" ]]; then
          log_info "Tag soca:OntapFirstSetup = true exist on this FSx for NetApp ONTAP, processing to CIFS share creation and SVM conf"
          # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


  
    

    function ontap_rest_wrapper () {
      local HTTP_METHOD
      local API_RESOURCE
      local FSX_ENDPOINT
      local FSX_ADMIN_AUTH
      local DATA
      for arg in "$@"; do
          case $arg in
              --method=*) HTTP_METHOD="${arg#*=}" ;;
              --resource=*) API_RESOURCE="${arg#*=}" ;;
              --endpoint=*) FSX_ENDPOINT="${arg#*=}" ;;
              --auth=*) FSX_ADMIN_AUTH="${arg#*=}" ;;
              --data=*) DATA="${arg#*=}" ;;
              *) exit_fail "Unknown arg ${arg} for ontap_rest_wrapper";;
          esac
      done

      if [[ -z "${DATA}" ]]; then
        curl -u "${FSX_ADMIN_AUTH}" -sk \
        -X "${HTTP_METHOD}" \
        "${FSX_ENDPOINT}${API_RESOURCE}" \
        -H "accept: application/hal+json" \
        -H "Content-Type: text/plain"

      else
        curl -u "${FSX_ADMIN_AUTH}" -sk \
          -X "${HTTP_METHOD}" \
          "${FSX_ENDPOINT}${API_RESOURCE}" \
          -H "accept: application/hal+json" \
          -H "Content-Type: text/plain" \
          -d "${DATA}"
      fi
    }

    function fsx_ontap_first_setup {
      # This function finalize FSxN setup and is executed only once when using a brand new FSx for NetApp ONTAP
      # 1 - Register LDAP/AD Client on the SVM
      # 2 - Create UNIX/NTFS Name Mapping to ensure correct ACL between Windows and Linux
      # 3 - Create CIFS share
      # 4 - Update default permissions when file/folder is created from Windows:
      # - File: 644
      # - Folder: 755
      local FSX_ONTAP_VOLUME_ID="${1}"

      if [[ -z "${FSX_ONTAP_VOLUME_ID}" ]]; then
        exit_fail "FSX_ONTAP_VOLUME_ID as first parameter is needed for fsx_ontap_first_setup"
      fi

      if ! verify_package_installed jq; then
        log_info "jq not found, installing it ..."
        packages_install jq
      fi

      # Query FSx APIs and retrieve Volume/SVM information
      local FSX_DESCRIBE_VOLUME=$(aws_cli fsx describe-volumes --volume-ids ${FSX_ONTAP_VOLUME_ID})
      local FSX_VOLUME_SVM_ID=$(echo ${FSX_DESCRIBE_VOLUME} | jq -r '.Volumes[0].OntapConfiguration.StorageVirtualMachineId // "NO_VALUE"')
      local FSX_VOLUME_JUNCTION_PATH=$(echo ${FSX_DESCRIBE_VOLUME} | jq -r '.Volumes[0].OntapConfiguration.JunctionPath // "NO_VALUE"')
      local FSX_FILESYSTEM_ID=$(echo ${FSX_DESCRIBE_VOLUME} | jq -r '.Volumes[0].FileSystemId // "NO_VALUE"')

      if [[ "${FSX_VOLUME_SVM_ID}" == "NO_VALUE" || "${FSX_VOLUME_JUNCTION_PATH}" == "NO_VALUE" || "${FSX_FILESYSTEM_ID}" == "NO_VALUE" ]]; then
        exit_fail "Unable to determine required values for FSX Volume ${FSX_ONTAP_VOLUME_ID}. Details- FSX_VOLUME_SVM_ID=${FSX_VOLUME_SVM_ID}, FSX_VOLUME_JUNCTION_PATH=${FSX_VOLUME_JUNCTION_PATH}, FSX_FILESYSTEM_ID=${FSX_FILESYSTEM_ID}"
      fi

      # Retrieve the FSx SVM associated to the volume
      local FSX_DESCRIBE_SVM=$(aws_cli fsx describe-storage-virtual-machines --storage-virtual-machine-ids ${FSX_VOLUME_SVM_ID})
      local FSX_SVM_NAME=$(echo ${FSX_DESCRIBE_SVM} | jq -r  '.StorageVirtualMachines[0].Name // "NO_VALUE"')

      if [[ "${FSX_SVM_NAME}" == "NO_VALUE" ]]; then
        exit_fail "Unable to determine required values for FSX Storage Virtual Machine. Details, FSX_SVM_NAME=${FSX_SVM_NAME}"
      fi

      # Retrieve filesystem and tag containing Secret Manager information
      local FSX_DESCRIBE_FILESYSTEM=$(aws_cli fsx describe-file-systems --file-system-ids ${FSX_FILESYSTEM_ID})
      local FSX_ENDPOINT_MANAGEMENT="https://$(echo ${FSX_DESCRIBE_FILESYSTEM} | jq -r '.FileSystems[0].OntapConfiguration.Endpoints.Management.DNSName // "NO_VALUE"')"
      local FSX_FILESYSTEM_TAG_FSX_ADMIN_SECRET=$(echo ${FSX_DESCRIBE_FILESYSTEM} | jq -r '.FileSystems[0].Tags[] | select(.Key == "soca:FsxAdminSecretName") | .Value')

      if [[ "${FSX_ENDPOINT_MANAGEMENT}" == "NO_VALUE" ]]; then
        exit_fail "Unable to determine FSX Endpoint Management . Details - FSX_ENDPOINT_MANAGEMENT=${FSX_ENDPOINT_MANAGEMENT}"
      fi

      if [[ -z "${FSX_FILESYSTEM_TAG_FSX_ADMIN_SECRET}" ]]; then
        exit_fail "Unable to proceed to FSx ONTAP first setup because tag soca:FsxAdminSecretName is missing"
      else
        log_info "Retrieving fsxadmin credentials from ${FSX_FILESYSTEM_TAG_FSX_ADMIN_SECRET}"
        local FSX_ADMIN_SECRETMANAGER_ID=$(get_secret "${FSX_FILESYSTEM_TAG_FSX_ADMIN_SECRET}")
        local FSX_ADMIN_USER=$(echo ${FSX_ADMIN_SECRETMANAGER_ID} | jq -r ". | fromjson.username")
        local FSX_ADMIN_PASSWORD=$(echo ${FSX_ADMIN_SECRETMANAGER_ID} | jq -r ". | fromjson.password")
      fi

      # Active Directory information for SVM domain join
      local DS_DOMAIN_NAME=$(echo ${FSX_DESCRIBE_SVM} | jq -r '.StorageVirtualMachines[0].ActiveDirectoryConfiguration.SelfManagedActiveDirectoryConfiguration.DomainName // "NO_VALUE"')
      local DS_DOMAIN_BASE=$(echo "${DS_DOMAIN_NAME}" | sed 's/\./,DC=/g' | sed 's/^/DC=/')
      local DS_SHORT_NAME=$(echo "${DS_DOMAIN_NAME%%.*}" | cut -c1-15 | tr '[:lower:]' '[:upper:]')


      if [[ "${DS_DOMAIN_NAME}" == "NO_VALUE" ]]; then
        exit_fail "Unable to determine AD required values for FSX SVM Details- DS_DOMAIN_NAME=${DS_DOMAIN_NAME}"
      fi

      # Replace / with _ on Share name: e.g: if junction path is /data then CIFS share name will be data
      local FSX_ONTAP_CIFS_SHARE_NAME=$(echo "${FSX_VOLUME_JUNCTION_PATH}" | sed 's|/|_|g; s/^_//')

      log_info "About to configure FSxN SVM ${FSX_SVM_NAME} for first launch"
      pushd ${SOCA_BOOTSTRAP_ASSETS_FOLDER}

      # First, get the SVM UUID associated to SVM
      log_info "Retrieve SVM UUID: GET ${FSX_ENDPOINT_MANAGEMENT}/api/svm/svms?name=${FSX_SVM_NAME}"
      FSX_SVM_UUID=$(ontap_rest_wrapper --auth="${FSX_ADMIN_USER}:${FSX_ADMIN_PASSWORD}" \
        --endpoint="${FSX_ENDPOINT_MANAGEMENT}" \
        --method="GET" \
        --resource="/api/svm/svms?name=${FSX_SVM_NAME}" | jq -r '.records[0].uuid')

      if [[ -z "${FSX_SVM_UUID}" ]]; then
        exit_fail "Unable to retrieve SVM UUID for ${FSX_SVM_NAME}, are you sure the SVM exists?"
      fi

      # vserver services name-service ldap client create -client-config ldap_config -ad-domain "${DS_DOMAIN_NAME}" -base-dn "${DS_DOMAIN_BASE}" -schema AD-IDMU -vserver "${FSX_SVM_NAME}";
      # vserver services name-service ldap create -vserver "${FSX_SVM_NAME}" -client-config ldap_config;
      log_info "Configuring LDAP Name Service: POST ${FSX_ENDPOINT_MANAGEMENT}/api/name-services/ldap"
      ontap_rest_wrapper --auth="${FSX_ADMIN_USER}:${FSX_ADMIN_PASSWORD}" \
       --endpoint="${FSX_ENDPOINT_MANAGEMENT}" \
       --method="POST" \
       --resource="/api/name-services/ldap" \
       --data="{
            \"svm\": { \"uuid\": \"${FSX_SVM_UUID}\" },
            \"ad_domain\": \"${DS_DOMAIN_NAME}\",
            \"base_dn\": \"${DS_DOMAIN_BASE}\",
            \"schema\": \"AD-IDMU\"
       }"

      # vserver services name-service ns-switch modify -vserver "${FSX_SVM_NAME}" -database passwd,group,namemap -sources ldap;
      log_info "Configuring LDAP Name Service: PATCH ${FSX_ENDPOINT_MANAGEMENT}/api/svm/svms/${FSX_SVM_UUID}"
      ontap_rest_wrapper --auth="${FSX_ADMIN_USER}:${FSX_ADMIN_PASSWORD}" \
       --endpoint="${FSX_ENDPOINT_MANAGEMENT}" \
       --method="PATCH" \
       --resource="/api/svm/svms/${FSX_SVM_UUID}" \
       --data="{
            \"nsswitch\": { \"passwd\": [\"ldap\"], \"group\": [\"ldap\"],\"namemap\": [\"ldap\"]  }
       }"

      # vserver name-mapping create -vserver "${FSX_SVM_NAME}" -direction win-unix -position 1 -pattern ${DS_SHORT_NAME}\\(.+) -replacement \1;
      log_info "Configuring win-unix name mapping: POST ${FSX_ENDPOINT_MANAGEMENT}/api/name-services/name-mappings"
      ontap_rest_wrapper --auth="${FSX_ADMIN_USER}:${FSX_ADMIN_PASSWORD}" \
       --endpoint="${FSX_ENDPOINT_MANAGEMENT}" \
       --method="POST" \
       --resource="/api/name-services/name-mappings" \
       --data="{
            \"svm\": { \"uuid\": \"${FSX_SVM_UUID}\" },
            \"direction\": \"win-unix\",
            \"index\": \"1\",
            \"pattern\": \"${DS_SHORT_NAME}\\\(.+)\",
            \"replacement\": \"\\\1\"
       }"

      # vserver name-mapping create -vserver "${FSX_SVM_NAME}" -direction unix-win -position 1 -pattern (.+) -replacement ${DS_SHORT_NAME}\\\1;
      log_info "Configuring unix-win name mapping: POST ${FSX_ENDPOINT_MANAGEMENT}/api/name-services/name-mappings"
      ontap_rest_wrapper --auth="${FSX_ADMIN_USER}:${FSX_ADMIN_PASSWORD}" \
       --endpoint="${FSX_ENDPOINT_MANAGEMENT}" \
       --method="POST" \
       --resource="/api/name-services/name-mappings" \
       --data="{
            \"svm\": { \"uuid\": \"${FSX_SVM_UUID}\" },
            \"direction\": \"unix-win\",
            \"index\": \"1\",
            \"pattern\": \"(.+)\",
            \"replacement\": \"${DS_SHORT_NAME}\\\(.+)\"
       }"

      # vserver nfs modify -vserver "${FSX_SVM_NAME}" -v4-id-domain "${DS_DOMAIN_NAME}";
      log_info "Modifying nfs -v4-id-domain: PATCH ${FSX_ENDPOINT_MANAGEMENT}/api/protocols/nfs/services/${FSX_SVM_UUID}"
      ontap_rest_wrapper --auth="${FSX_ADMIN_USER}:${FSX_ADMIN_PASSWORD}" \
       --endpoint="${FSX_ENDPOINT_MANAGEMENT}" \
       --method="PATCH" \
       --resource="/api/protocols/nfs/services/${FSX_SVM_UUID}" \
       --data="{
            \"protocol\": { \"v4_id_domain\": \"${DS_DOMAIN_NAME}\" }
       }"

      # vserver cifs share create -vserver "${FSX_SVM_NAME}" -share-name ${FSX_ONTAP_CIFS_SHARE_NAME} -path \\${FSX_VOLUME_JUNCTION_PATH};
      log_info "Creating CIFS share: POST ${FSX_ENDPOINT_MANAGEMENT}/api/protocols/cifs/shares"
      ontap_rest_wrapper --auth="${FSX_ADMIN_USER}:${FSX_ADMIN_PASSWORD}" \
       --endpoint="${FSX_ENDPOINT_MANAGEMENT}" \
       --method="POST" \
       --resource="/api/protocols/cifs/shares" \
       --data="{
            \"svm\": { \"uuid\": \"${FSX_SVM_UUID}\" },
            \"name\": \"${FSX_ONTAP_CIFS_SHARE_NAME}\",
            \"path\": \"\\${FSX_VOLUME_JUNCTION_PATH}\",
            \"file_umask\": \"133\",
            \"dir_umask\": \"133\"
      }"

      popd
    }
  

          fsx_ontap_first_setup "${MOUNT_TARGET}"
        else
          log_info "soca:OntapFirstSetup not present or not true, fsx_ontap_first_setup is not needed"
        fi
      fi

      if fstab_wrapper "${ENDPOINT} ${MOUNT_PATH} nfs4 ${MOUNT_OPTIONS} 0 0"; then
        log_info "Successfully mounted ${ENDPOINT} as ${MOUNT_PATH}"
      else
        if [[ ${ON_MOUNT_FAILURE} == "exit" ]]; then
          exit_fail "Unable to mount ${ENDPOINT} as ${MOUNT_PATH}"
        else
          log_warning "Unable to mount ${ENDPOINT} as ${MOUNT_PATH}, ignoring"
        fi
      fi
    else
      log_warning "FSx ONTAP Filesystem ${MOUNT_TARGET}, mount path ${MOUNT_PATH} is not enabled. Skipping ... Detected enabled flag ${ENABLED}"
    fi
  }

# End: FSx OnTap mount

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: FSx OpenZFS mount

  

  # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



  function mount_fsx_openzfs () {
    # MOUNT_TARGET (required): FSx OpenZFS Filesytem ID. Used to determine actual mount endpoint if ENDPOINT is not set
    # MOUNT_PATH (required): Unix path to mount the EFS on
    # ON_MOUNT_FAILURE (required): What to do if the mount is not successful (exit or ignore)
    # MOUNT_OPTIONS (optional): NFS options to use
    # ENABLED (optional): Whether the automount is enabled

    local MOUNT_TARGET
    local MOUNT_PATH
    local MOUNT_OPTIONS
    local ON_MOUNT_FAILURE
    for arg in "$@"; do
        case $arg in
            --mount-target=*) MOUNT_TARGET="${arg#*=}" ;;
            --mount-path=*) MOUNT_PATH="${arg#*=}" ;;
            --mount-options=*) MOUNT_OPTIONS="${arg#*=}" ;;
            --on-mount-failure=*) ON_MOUNT_FAILURE="${arg#*=}" ;;
            --enabled=*) ENABLED="${arg#*=}" ;;
            *) exit_fail "Unknown arg ${arg} for mount_fsx_openzfs";;
        esac
    done

    if [[ -z "${ENABLED}" ]]; then
      ENABLED="true"
      log_warning "--enabled not set, default to ${ENABLED}"
    fi

    if [[ -z "${MOUNT_PATH}" ]]; then
      exit_fail "--mount-path not set for mount_fsx_openzfs"
    fi

    if [[ -z "${ON_MOUNT_FAILURE}" ]]; then
      ON_MOUNT_FAILURE="ignore"
      log_warning "--on-mount-failure not specified, default to ${ON_MOUNT_FAILURE}"
    fi

    if [[ -z ${MOUNT_OPTIONS} ]]; then
      MOUNT_OPTIONS="nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport"
      log_warning "--mount-options not specified, default to ${MOUNT_OPTIONS}"
    fi

    if [[ "${ENABLED}" == "true" ]]; then
      if [[ -z "${MOUNT_TARGET}" ]]; then
        exit_fail "--mount-target not set for mount_fsx_openzfs"
      else
        local DNS_NAME=$(aws_cli fsx describe-file-systems --file-system-id ${MOUNT_TARGET} --query 'FileSystems[0].DNSName')
        if [[ -z ${DNS_NAME} ]]; then
          exit_fail "Unable to find FileSystems[0].DNSName of ${MOUNT_TARGET}. API Result: ${DNS_NAME}"
        fi
          ENDPOINT="${DNS_NAME}:/fsx"
      fi

      if fstab_wrapper "${ENDPOINT} ${MOUNT_PATH} nfs4 ${MOUNT_OPTIONS} 0 0"; then
        log_info "Successfully mounted ${ENDPOINT} as ${MOUNT_PATH}"
      else
        if [[ ${ON_MOUNT_FAILURE} == "exit" ]]; then
          exit_fail "Unable to mount ${ENDPOINT} as ${MOUNT_PATH}"
        else
          log_warning "Unable to mount ${ENDPOINT} as ${MOUNT_PATH}, ignoring"
        fi
      fi
    else
      log_warning "FSx OpenZFS Filesystem ${MOUNT_TARGET}, mount path ${MOUNT_PATH} is not enabled. Skipping ... Detected enabled flag ${ENABLED}"
    fi
  }


# End: EFS mount

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: EFS mount

  

  # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



  function mount_nfs () {
    # MOUNT_TARGET (required):NFS Endpoint
    # MOUNT_PATH (required): Unix path to mount the filesystem on
    # ON_MOUNT_FAILURE (required): What to do if the mount is not successful (exit or ignore)
    # MOUNT_OPTIONS (optional): NFS options to use
    # ENABLED (optional): Whether the automount is enabled


      local MOUNT_TARGET
      local MOUNT_PATH
      local MOUNT_OPTIONS
      local ON_MOUNT_FAILURE
      for arg in "$@"; do
          case $arg in
              --mount-target=*) MOUNT_TARGET="${arg#*=}" ;;
              --mount-path=*) MOUNT_PATH="${arg#*=}" ;;
              --mount-options=*) MOUNT_OPTIONS="${arg#*=}" ;;
              --on-mount-failure=*) ON_MOUNT_FAILURE="${arg#*=}" ;;
              --enabled=*) ENABLED="${arg#*=}" ;;
              *) exit_fail "Unknown arg ${arg} for mount_efs";;
          esac
      done

      if [[ -z "${ENABLED}" ]]; then
        ENABLED="true"
        log_warning "--enabled not set, default to ${ENABLED}"
      fi

      if [[ -z "${MOUNT_PATH}" ]]; then
        exit_fail "--mount-path not set for mount_nfs"
      fi

      if [[ -z "${ON_MOUNT_FAILURE}" ]]; then
        ON_MOUNT_FAILURE="ignore"
        log_warning "--mount-fail not specified, default to ${ON_MOUNT_FAILURE}"
      fi

      if [[ -z "${MOUNT_TARGET}" ]]; then
        exit_fail "--mount-target not set for mount_nfs"
      fi

      if [[ -z ${MOUNT_OPTIONS} ]]; then
        MOUNT_OPTIONS="nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport"
        log_warning "--mount-options not specified, default to ${MOUNT_OPTIONS}"
      fi

      if [[ "${ENABLED}" == "true" ]]; then
        if fstab_wrapper "${ENDPOINT} ${MOUNT_PATH} nfs4 ${MOUNT_OPTIONS} 0 0"; then
          log_info "Successfully mounted ${ENDPOINT} as ${MOUNT_PATH}"
        else
          if [[ ${ON_MOUNT_FAILURE} == "exit" ]]; then
            exit_fail "Unable to mount ${ENDPOINT} as ${MOUNT_PATH}"
          else
            log_warning "Unable to mount ${ENDPOINT} as ${MOUNT_PATH}, ignoring"
          fi
        fi
      else
        log_warning "Standalone NFS Endpoint ${MOUNT_TARGET}, mount path ${MOUNT_PATH} is not enabled. Skipping ... Detected enabled flag ${ENABLED}"
      fi
  }

# End: EFS mount

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: Amazon S3 MountPoint

  

  function mount_s3 () {
      # MOUNT_TARGET (required): Bucket name
      # MOUNT_PATH (required): Unix path to mount the EFS on
      # ON_MOUNT_FAILURE (required): What to do if the mount is not successful (exit or ignore)
      # MOUNT_OPTIONS (optional): NFS options to use
      # ENABLED (optional): Whether the automount is enabled
      pushd ${SOCA_BOOTSTRAP_ASSETS_FOLDER}

      if ! verify_package_installed mount-s3; then
        log_info "mount-s3 not found, installing it ..."
        local MACHINE=$(uname -m)
        local MOUNT_S3_INSTALLER_URL
        local MOUNT_S3_INSTALLER_HASH
        local MOUNT_S3_INSTALLER_FILENAME="$(date +%s)_mountpoint-s3.rpm"
        if [[ ${MACHINE} == "x86_64" ]]; then
          MOUNT_S3_INSTALLER_URL="https://s3.amazonaws.com/mountpoint-s3-release/1.14.0/x86_64/mount-s3-1.14.0-x86_64.rpm"
          MOUNT_S3_INSTALLER_HASH="ea6f6f76602b0034642a88a8ce31542a185c36c9fa5e50c49dffe445b8b70cd7"
        else
          MOUNT_S3_INSTALLER_URL="https://s3.amazonaws.com/mountpoint-s3-release/1.14.0/arm64/mount-s3-1.14.0-arm64.rpm"
          MOUNT_S3_INSTALLER_HASH="5c13de3fa0a8fd884444c5bf149cc4c3967aadad5c6fc4925df2529d4a83a5dd"
        fi
      fi

      file_download --download-url="${MOUNT_S3_INSTALLER_URL}" --save-as="${MOUNT_S3_INSTALLER_FILENAME}" --sha256-checksum="${MOUNT_S3_INSTALLER_HASH}"
      packages_install ${MOUNT_S3_INSTALLER_FILENAME}

      local MOUNT_TARGET
      local MOUNT_PATH
      local MOUNT_OPTIONS
      local ON_MOUNT_FAILURE

      for arg in "$@"; do
          case $arg in
              --mount-target=*) MOUNT_TARGET="${arg#*=}" ;;
              --mount-path=*) MOUNT_PATH="${arg#*=}" ;;
              --mount-options=*) MOUNT_OPTIONS="${arg#*=}" ;;
              --on-mount-failure=*) ON_MOUNT_FAILURE="${arg#*=}" ;;
              --enabled=*) ENABLED="${arg#*=}" ;;
              *) exit_fail "Unknown arg ${arg} for mount_efs";;
          esac
      done

      if [[ -z "${ENABLED}" ]]; then
        ENABLED="true"
        log_warning "--enabled not set, default to ${ENABLED}"
      fi

      if [[ -z "${MOUNT_PATH}" ]]; then
        exit_fail "--mount-path not set for mount_s3"
      fi

      if [[ -z "${ON_MOUNT_FAILURE}" ]]; then
        ON_MOUNT_FAILURE="ignore"
        log_warning "--on-mount-failure not specified, default to ${ON_MOUNT_FAILURE}"
      fi

      if [[ -z "${MOUNT_TARGET}" ]]; then
        exit_fail "--mount-target not set for mount_s3"
      fi

      if [[ -z "${MOUNT_OPTIONS}" ]]; then
        MOUNT_OPTIONS=""
        log_warning "no --mount-options specified, default to ${MOUNT_OPTIONS}"
      fi

       if [[ "${ENABLED}" == "true" ]]; then
        # Amazon S3 MountPoint does not currently support automatically mounting a bucket at system boot time.
        # A tracking issue is open for fstab support: https://github.com/awslabs/mountpoint-s3/issues/44
        MOUNT_S3_BIN=$(which mount-s3)
        FUSERMOUNT_BIN=$(which fusermount)

        log_info "Creating ${MOUNT_POINT} if needed"
        mkdir -p ${MOUNT_POINT}

        echo "[Unit]
Description=Amazon S3 Mountpoint for "${MOUNT_PATH}"
Wants=network.target
AssertPathIsDirectory="${MOUNT_PATH}"

[Service]
Type=forking
User=root
Group=root
ExecStart=${MOUNT_S3_BIN} "${MOUNT_TARGET}" "${MOUNT_PATH}" "${MOUNT_OPTIONS}"
ExecStop=${FUSERMOUNT_BIN} -u ${MOUNT_PATH}

[Install]
WantedBy=remote-fs.target"  > /etc/systemd/system/soca-s3-${MOUNT_TARGET}-automount.service

        log_info "Enabling & start soca-s3-${MOUNT_TARGET}-automount.service"
        systemctl enable "soca-s3-${MOUNT_TARGET}-automount.service"

        if systemctl start "soca-s3-${MOUNT_TARGET}-automount.service"; then
          log_info "Successfully mounted ${MOUNT_TARGET} as ${MOUNT_PATH}"
        else
          if [[ ${ON_MOUNT_FAILURE} == "exit" ]]; then
            exit_fail "Unable to mount ${MOUNT_TARGET} as ${MOUNT_PATH}. Did the IAM role has permissions to mount the bucket? Check /var/log/message for more info"
          else
            log_warning "Unable to mount ${MOUNT_TARGET} as ${MOUNT_PATH}, ignoring"
          fi
        fi
      else
        log_warning "S3 Bucket ${MOUNT_TARGET}, mount path ${MOUNT_PATH} is not enabled. Skipping ... Detected enabled flag ${ENABLED}"
      fi
      popd
    }

# End: Amazon S3 MountPoint

# Include EPEL repo in case jq is not shipped via the distro default packages repository
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: Install EPEL repository
function install_epel () {
    # Note: CRB / Powertool repo for RHEL8+ based distro are managed via system_packages.sh.j2
    # install_epel is also called at the beginning of system_packages.sh.j2

    pushd "${SOCA_BOOTSTRAP_ASSETS_FOLDER}"
    local EPEL_URL
    local EPEL_RPM

    if ls -ltr /etc/yum.repos.d/ | grep epel; then
      log_info "EPEL repo are already installed on this machine"
    else
      log_info "EPEL repo not found, installing it ..."

      

         
           EPEL_URL="https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm"
         
        log_info "Downloading EPEL RPM from ${EPEL_URL}"
        file_download --download-url="${EPEL_URL}" --save-as="epel-installer.rpm"
        packages_install "epel-installer.rpm"

      
    fi

    popd

}
install_epel

source /etc/environment

# Ensure SocaFileSystemAutoMount is only executed once the entire SSM tree is created
while ! aws_cli ssm get-parameter --name "/soca/soca-rhel12/cdk_completed" > /dev/null 2>&1; do
    log_info "/soca/soca-rhel12/cdk_completed not found on SSM, SOCA is still being created"
    sleep 120
done

# Retrieve SocaConfig "/configuration/Filesystems" which contains all the FileSystem mount logic, return a dictionary of key/v
SOCA_FILESYSTEMS_SSM_TREE=$(aws_cli ssm get-parameters-by-path --path "/soca/soca-rhel12/configuration/FileSystems"  \
  --recursive \
  --with-decryption \
  --query "Parameters[*].{Name:Name,Value:Value}" \
  --output json)

log_info "Retrieved SOCA FileSystem Tree: ${SOCA_FILESYSTEMS_SSM_TREE}"

# Install jq if not already there
if ! verify_package_installed jq; then
  log_info "jq not found, installing it ..."
  packages_install jq
fi

FS_MAP=$(echo "${SOCA_FILESYSTEMS_SSM_TREE}" | jq --arg prefix "/soca/soca-rhel12" -r '
  def walk(f):
  . as $in |
  if type == "object" then
    reduce keys_unsorted[] as $key (
      {}; . + {($key): ($in[$key] | walk(f))}
    )
  elif type == "array" then
    map(walk(f))
  else
    f
  end;

  map({(.Name): .Value}) | add |
  to_entries |
  map(select(.key | startswith($prefix + "/configuration/FileSystems/"))) |
  map(.key |= sub($prefix + "/configuration/FileSystems/"; "")) |
  reduce .[] as $item ({};
    ($item.key | split("/")) as $parts |
    setpath($parts; $item.value)
  ) |
  walk(
    if type == "object" then
      with_entries(
        if .value | type == "object" and length == 1 and (keys[0] == values[0] | keys[0])
        then .value = .value[keys[0]]
        else .
        end
      )
    else .
    end
  )
')

echo "${FS_MAP}" | jq -r 'keys[]' | while read FS_NAME; do
  # Filesystem Provider (fsx_ontap, fsx_lustre, efs ...)
  PROVIDER=$(echo "${FS_MAP}" | jq -r ".${FS_NAME}.provider")

  # Whether or not the FSx is enabled or not
  ENABLED=$(echo "${FS_MAP}" | jq -r ".${FS_NAME}.enabled // \"true\"")

  # Unix path where to mount this filesystem
  MOUNT_PATH=$(echo "${FS_MAP}" | jq -r ".${FS_NAME}.mount_path")

  # Endpoint to be mounted (volume ID, filesystem ID ...)
  MOUNT_TARGET=$(echo "${FS_MAP}" | jq -r ".${FS_NAME}.mount_target")

  # Option for the mount
  MOUNT_OPTIONS=$(echo "$FS_MAP" | jq -r ".${FS_NAME}.mount_options")

  # What to do if the mount is not successful (either ignore or exit)
  ON_MOUNT_FAILURE=$(echo "${FS_MAP}" | jq -r ".${FS_NAME}.on_mount_failure //  \"ignore\"")

  log_info "Processing ${PROVIDER}: $(echo "${FS_MAP}" | jq -r ".${FS_NAME}")"

  case "${PROVIDER}" in
  "efs")
    MOUNT_FUNCTION="mount_efs"
    ;;
  "nfs")
    MOUNT_FUNCTION="mount_nfs"
    ;;
  "fsx_lustre")
    MOUNT_FUNCTION="mount_fsx_lustre"
    ;;
  "fsx_ontap")
    MOUNT_FUNCTION="mount_fsx_ontap"
    ;;
  "fsx_openzfs")
    MOUNT_FUNCTION="mount_openzfs"
    ;;
  "s3")
    MOUNT_FUNCTION="mount_s3"
    ;;
  *)
    exit_fail "Unrecognized Storage Provider ${PROVIDER} for ${FS_NAME} , must be efs / nfs / fsx_lustre / fsx_ontap / fsx_openzfs or s3"
    ;;
  esac

  if ! eval ${MOUNT_FUNCTION} --mount-path="${MOUNT_PATH}" \
        --mount-target="${MOUNT_TARGET}" \
        --mount-options="${MOUNT_OPTIONS}" \
        --on-mount-failure="${ON_MOUNT_FAILURE}" \
        --enabled="${ENABLED}"; then

      exit_fail "Error while trying to mount ${MOUNT_TARGET} via ${MOUNT_FUNCTION}, check SocaFileSystemAutoMount log"
  fi

done

log_info "SocaFileSystemsAutoMount Completed"