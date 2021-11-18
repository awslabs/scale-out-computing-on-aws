#!/bin/bash -e

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

# Node.js and NPM will be installed if needed
# A custom python3 virtual environment will be created

realpath() {
    [[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
}

PYTHON=$(command -v python) # Change to custom Python3 if needed
INSTALLER_DIRECTORY=$(dirname $(realpath "$0"))
QUIET_MODE="false" # change to "false" for more log
PYTHON_VENV="$INSTALLER_DIRECTORY/resources/src/envs/venv-py-installer" # Python Virtual Environment. It's not recommended to change the value
NODEJS_BIN="https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh"
export NVM_DIR="$INSTALLER_DIRECTORY/resources/src/envs/.nvm"

# shellcheck disable=SC2164
cd "$INSTALLER_DIRECTORY"

echo "======= Checking system pre-requisites ======="
echo "Verifying Python3 interpreter"
# shellcheck disable=SC2181
if [[ $? -ne 0 ]]; then
    echo "Python3 is not installed. Please download and install it from https://www.python.org/downloads/"
    exit 1
else
    # Verify Python version
    PYTHON_VERSION=$($PYTHON -c "import sys;print(sys.version_info.major)")
    if [[ $PYTHON_VERSION -ne 3 ]]; then
        echo "$PYTHON is version $PYTHON_VERSION. Python3 is required, checking if there is a py3 interpreter install on the system"
        PYTHON=$(command -v python3)
        if [[ $? -ne 0 ]]; then
            echo "Unable to find python3. Please download and install it from https://www.python.org/downloads/"
            exit 1
        else
            echo "Found python3: $PYTHON"
        fi
    fi
fi

# Check if user is already running on a virtual environment
if [[ -n $VIRTUAL_ENV ]]; then
  echo "=====ATTENTION===="
  echo "You are currently using an existing Python virtual environment."
  echo "To prevent dependencies errors, It's highly recommended to exit your virtual environment first and re-launch the installer"
  echo "SOCA will create its own virtual environment and configure all required dependencies"
  echo "=================="
  read -rp "Do you want to continue with your existing virtual environment? (yes/no) " EXISTINGVIRTENV
    case $EXISTINGVIRTENV in
        yes )
          if [[ $QUIET_MODE = "true" ]]; then
            pip3 install --upgrade pip --quiet
            pip3 install -r resources/src/requirements.txt --quiet
          else
            pip3 install --upgrade pip
            pip3 install -r resources/src/requirements.txt
          fi
          ;;
        no ) exit 1;;
        * ) echo "Please answer yes or no."
          exit 1 ;;
    esac
  sleep 5
else
  # Check if Python Virtual environment exist
  # If not, create the venv and install required python libraries
  if [[ ! -d $PYTHON_VENV ]]; then
      echo "No Python virtual environment found. Creating one ..."
      $PYTHON -m venv $PYTHON_VENV
      # shellcheck disable=SC1090
      . "$PYTHON_VENV/bin/activate"
      echo "Installing/upgrading required dependencies (this can take a couple of minutes)"
      if [[ $QUIET_MODE = "true" ]]; then
        pip3 install --upgrade pip --quiet
        pip3 install -r resources/src/requirements.txt --quiet
      else
        pip3 install --upgrade pip
        pip3 install -r resources/src/requirements.txt
      fi
  else
    # Load Python environment
    echo "Loading Python Virtual Environment"
    source "$PYTHON_VENV/bin/activate"
  fi
fi

# Install local NodeJS environment and CDK
if [[ ! -d $NVM_DIR ]]; then
  mkdir -p $NVM_DIR
  echo "Local NodeJS environment not detected, creating one ..."
  echo "Downloading $NODEJS_BIN"
  curl --silent -o- "$NODEJS_BIN" | bash
  echo "Installing Node & NPM via nvm"
  source "$NVM_DIR/nvm.sh"  # This loads nvm
  # shellcheck disable=SC1090
  source "$NVM_DIR/bash_completion"
  nvm install node
  npm install -g aws-cdk
else
  source "$NVM_DIR/nvm.sh"  # This loads nvm
  source "$NVM_DIR/bash_completion"
fi

# Check if aws cli (https://aws.amazon.com/cli/) is installed
PIP3=$(command -v pip3)
command -v aws > /dev/null
# shellcheck disable=SC2181
if [[ $? -ne 0 ]]; then
    echo "AWSCLI not detected."
    while true; do
    read -rp "Do you want to automatically install aws cli and configure it? You will need to have a valid pair of access/secret key. You can generate them on the AWS Console IAM section (yes/no) " AWSCLIINSTALL
    case $AWSCLIINSTALL in
        yes ) $PIP3 install awscli
          echo "AWS CLI installed. Running 'aws configure' to configure your AWS CLI environment:"
          aws configure
          ;;
        no ) exit 1;;
        * ) echo "Please answer yes or no."
          exit 1;;
    esac
  done
fi

# Set default region, fallback to Virginia if not defined (Used by install_soca.py)
export AWS_DEFAULT_REGION=$(cat ~/.aws/config | grep region | awk '{print $3}' | head -n 1)
if [[ $AWS_DEFAULT_REGION == "" ]]; then
  export AWS_DEFAULT_REGION="us-east-1" ;
fi

echo "======= Pre-requisites completed. Launching installer ======="

# Launch actual installer
resources/src/install_soca.py "$@"
