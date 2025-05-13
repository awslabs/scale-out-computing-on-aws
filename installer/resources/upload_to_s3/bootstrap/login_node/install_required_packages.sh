# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: Install/Update Required Linux Packages

# Do not include this template from another template in your bootstrap sequence. Instead render and save it as a file.

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
      log_info "${DOWNLOAD_URL} seems to be a S3 URL"
      DOWNLOAD_TYPE="s3"
  else
       log_info "${DOWNLOAD_URL} seems to be an HTTP URL"
      DOWNLOAD_TYPE="http"
  fi

  if [[ -z ${DOWNLOAD_URL} ]]; then
    exit_fail " --download-url  not found for file_download"
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
    local S3_ACTION

    if [[ "${DOWNLOAD_URL}" =~ /$ ]]; then
        log_info "${DOWNLOAD_URL} ends with /, using s3 sync"
        S3_ACTION="sync"
    else
        log_info "${DOWNLOAD_URL} does not ends with /, using s3 cp"
        S3_ACTION="cp"
    fi

    if aws_cli s3 ${S3_ACTION} ${DOWNLOAD_URL} ${SAVE_AS} --quiet; then
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

  
    packages_exec_command yum remove -y "${@}"
  
}

function packages_install () {
  # Install specified packages (e.g: packages_install pkg1 pkg2 ... pkgN)
  if [[ $# -eq 0 ]]; then
    exit_fail "packages_install - No package list specified. Exiting... "
  fi

  
    packages_exec_command yum install -y "${@}"
  
}

function verify_package_installed () {
  # Return "true" is a given package is installed (e.g: verify_package_installed pkg_name)
  if [[ $# -eq 0 ]]; then
    exit_fail "verify_package_installed - No package list specified. Exiting... "
  fi

  
    rpm -q ${1} &> /dev/null && return 0 || return 1
  
}

function packages_clean () {
  # Remove un-necessary packages
  
    packages_exec_command yum clean all
  
}

function packages_generic_command() {
  # generic wrapper for commands other than install/remove
  
    packages_exec_command yum "${@}"
  
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
    local AWS_API_CALL="${AWS} --region eu-west-3 $*"
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
  local SOCA_IDENTIFIER="# SOCA Environment Variable, [SOCA_DO_NOT_DELETE]" # added to each entry

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
        printf "${SOCA_IDENTIFIER}\nexport ${VARIABLE_NAME}=${VARIABLE_VALUE}\n"
      } >> /etc/environment
  fi
  # Reload your env
  source /etc/environment
}
# End - Setup /etc/environment


export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/pbs/bin:/opt/pbs/sbin:/opt/soca/soca-demoparis:${PATH}

# Source environment
source /etc/environment

# Source SOCA_PYTHON if exist
SOCA_PYTHON_ENV_PATH="/opt/soca/soca-demoparis/python/latest/soca_python.env"

if [[ -f "${SOCA_PYTHON_ENV_PATH}" ]]; then
    source "${SOCA_PYTHON_ENV_PATH}"
fi

# Add EPEL & Ubuntu equivalent
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

      
        log_info "EPEL is not supported on Amazon Linux 2023 https://docs.aws.amazon.com/linux/al2023/ug/compare-with-al2.html#epel"

      
    fi

    popd

}
install_epel

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Begin: Enable extra repo for Ubuntu https://help.ubuntu.com/community/Repositories/Ubuntu

# End: Enable extra repo for Ubuntu

function system_packages_install {
  log_info "# Begin: Install/Update Required Linux Packages"
  # Will Create a lock file to avoid re-installing packages if bootstrap has already been executed
  local PACKAGES_ALREADY_INSTALLED_FILE_LOCK="/root/.soca_preinstalled_packages_soca-demoparis.log"
  local SYSTEM_PKGS # List of packages to be installed on all nodes
  local USER_EXTRA_PKGS # Additional packages to install at runtime
  local ADD_PKGS # Custom list of packages to add based on distro, see below
  local REMOVE_PKGS # Custom list of packages to remove based on distro, see below see below

  # Include potential extra package specified by customer
  # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# List of new packages you would like to automatically install on all your SOCA nodes
# Ensure the packages are available on all distro, otherwise directly edit the ADD_PKGS directly on the "os" folder

USER_EXTRA_PKGS=(
  telnet
)

  if [[ ! -f "${PACKAGES_ALREADY_INSTALLED_FILE_LOCK}" ]]; then
    log_info "No preinstalled package log found on ${PACKAGES_ALREADY_INSTALLED_FILE_LOCK} - preparing BaseOS - amazonlinux2023 .."

    # Get list of Linux packages to install for each distribution
    
      # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Linux Base Packages for the following distributions:
# - Amazon Linux
# - RedHat Enterprise Linux
# - CentOS
# - Rocky Linux

# Note: EPEL repo (or equivalent) is enabled when applicable

# /!\ ATTENTION /!\
# Changing anything beyond this line could cause your SOCA environment to become unstable/crash
# If you want to add new packages:
# Option 1 - Edit the USER_EXTRA_PKGS on system_packages/user_extra_packages.sh.j2 (apply to all nodes type, executed at the beginning of the boostrap phase)
# Option 2 - Edit cluster_node_bootstrap/compute_node/04_setup_user_customization.sh.j2 to apply logic for each node type (executed at the end of the boostrap phase)

# (DO NOT MODIFY) Packages installed on ALL SOCA Nodes
SYSTEM_PKGS=(
  adcli
  authselect-compat
  autoconf
  automake
  avahi-libs
  bind-libs
  bind-libs-lite
  bind-license
  bind-utils
  bzip2
  bzip2-devel
  bzip2-libs
  c-ares
  chrony
  compat-openldap
  cmake3
  cpp
  cronie
  cups-libs
  cyrus-sasl
  cyrus-sasl-devel
  cyrus-sasl-gssapi
  dejavu-fonts-common
  dejavu-sans-fonts
  e2fsprogs
  e2fsprogs-libs
  elfutils-libelf-devel
  expat-devel
  fontconfig
  fontpackages-filesystem
  freetype
  gcc
  gcc-c++
  gcc-gfortran
  git
  glibc
  glibc-common
  glibc-devel
  glibc-headers
  gssproxy
  htop
  http-parser
  hwloc
  hwloc-devel
  hwloc-libs
  jq
  kernel
  kernel-devel
  kernel-headers
  keyutils
  keyutils-libs-devel
  krb5-devel
  krb5-libs
  krb5-workstation
  libICE
  libSM
  libX11
  libX11-common
  libX11-devel
  libXau
  libXext
  libXft
  libXrender
  libXt-devel
  libbasicobjects
  libcollection
  libcom_err
  libcom_err-devel
  libdhash
  libedit-devel
  libevent
  libffi-devel
  libgcc
  libgfortran
  libglvnd-devel
  libgomp
  libical libical-devel
  libini_config
  libipa_hbac
  libkadm5
  libldb
  libmpc
  libnfsidmap
  libpath_utils
  libpng
  libref_array
  libselinux
  libselinux-devel
  libselinux-python
  libselinux-utils
  libsepol
  libsepol-devel
  libsmbclient
  libss
  libsss_autofs
  libsss_certmap
  libsss_idmap
  libsss_nss_idmap
  libsss_sudo
  libstdc++
  libstdc++-devel
  libtalloc
  libtdb
  libtevent
  libtirpc
  libtool
  libtool-ltdl
  libverto-devel
  libverto-tevent
  libwbclient
  libxcb
  lshw
  lzma
  make
  mdadm
  mpfr
  ncurses-devel
  nfs-utils
  nss-pam-ldapd
  nvme-cli
  oddjob
  oddjob-mkhomedir
  openldap
  openldap-clients
  openldap-compat
  openldap-devel
  openssl
  openssl-devel
  openssl-libs
  openssh
  openssh-server
  pcre
  pcre-devel
  perl
  perl-Carp
  perl-Encode
  perl-Env
  perl-Exporter
  perl-File-Path
  perl-File-Temp
  perl-Filter
  perl-Getopt-Long
  perl-HTTP-Tiny
  perl-PathTools
  perl-Pod-Escapes
  perl-Pod-Perldoc
  perl-Pod-Simple
  perl-Pod-Usage
  perl-Scalar-List-Utils
  perl-Socket
  perl-Storable
  perl-Switch
  perl-Text-ParseWords
  perl-Time-HiRes
  perl-Time-Local
  perl-constant
  perl-libs
  perl-macros
  perl-parent
  perl-podlators
  perl-threads
  perl-threads-shared
  postgresql
  postgresql-contrib
  postgresql-devel
  postgresql-libs
  postgresql-server
  python-sssdconfig
  python3
  python3-devel
  python3-pip
  quota
  quota-nls
  readline-devel
  realmd
  redhat-lsb
  rpcbind
  rpm-build
  rsyslog
  samba-client-libs
  samba-common
  samba-common-libs
  samba-common-tools
  sssd
  sssd-ad
  sssd-client
  sssd-common
  sssd-common-pac
  sssd-ipa
  sssd-krb5
  sssd-krb5-common
  sssd-ldap
  sssd-proxy
  swig
  system-lsb
  systemd-devel
  tcl
  tcl-devel
  tcp_wrappers
  telnet
  tk
  tk-devel
  unixODBC
  unixODBC-devel
  vim
  wget
  xz
  xz-devel
  zlib
  zlib-devel
)

log_info "Customizing Linux packages installation for amazonlinux2023"

# Packages not available or with a different name in this distro
REMOVE_PKGS=(
  libselinux-python
  libverto-tevent
  system-lsb
  tcp_wrappers
  redhat-lsb
  dejavu-fonts-common
  postgresql
  postgresql-contrib
  postgresql-server
  compat-openldap
  http-parser
)

# New packages to add  (specific to this distro)
ADD_PKGS=(
  python3-libselinux
  dejavu-fonts-all
  postgresql15
  postgresql15-contrib
  postgresql15-server
  openldap-compat
)

if (uname -r | grep -q ^6.12.); then
  ADD_PKGS+=(kernel-devel-$(uname -r) kernel6.12-modules-extra)
else
  ADD_PKGS+=(kernel-devel-$(uname -r) kernel-modules-extra)
fi

log_info "Removing packages for ALI2023: ${REMOVE_PKGS[*]}"
log_info "Adding extra packages for ALI2023: ${ADD_PKGS[*]}"

    

    # Add distro specific packages and ensure uniqueness
    SYSTEM_PKGS=($(printf '%s\n' "${SYSTEM_PKGS[@]}" "${ADD_PKGS[@]}" | sort | uniq))

    # Avoid kernel update is Lustre is on the mount table as lustre-client is kernel specific.
    if cat /etc/fstab | grep -q lustre; then
      log_info "Lustre filesystem found in /etc/fstab. Removing kernel from package update to avoid version mismatch with lustre-client version"
      REMOVE_PKGS+=(kernel)
    fi

    # Ensure packages in REMOVE_PKGS won't be installed
    for pkg_to_remove in "${REMOVE_PKGS[@]}"; do
      SYSTEM_PKGS=($(printf '%s\n' "${SYSTEM_PKGS[@]}" | grep -vE "^${pkg_to_remove}$"))
      USER_EXTRA_PKGS=($(printf '%s\n' "${USER_EXTRA_PKGS[@]}" | grep -vE "^${pkg_to_remove}$"))
    done

    # Proceed to the actual installation
    packages_install ${SYSTEM_PKGS[@]} ${USER_EXTRA_PKGS[@]}

    # Create file to bypass package installation if we create an AMI from this machine
    touch ${PACKAGES_ALREADY_INSTALLED_FILE_LOCK}

    # Post Install commands
    

    # Prepare for reboot
    
      if [[ $(rpm -qa kernel | wc -l) -gt 1 ]]; then
        set_reboot_required "Kernel was updated during package install"
      fi
    

  else
    log_info "Existing Package log ${PACKAGES_ALREADY_INSTALLED_FILE_LOCK} found. Bypassing package installation steps. Remove this file if you have modified the list of package to install"
  fi
  log_info "End: Install/Update Required Linux Packages"
}
system_packages_install
# End: Install/Update Required Linux Packages