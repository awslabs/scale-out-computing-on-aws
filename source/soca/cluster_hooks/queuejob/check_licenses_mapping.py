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
This hook reject the job if the user is not allowed to use the licenses
Doc:
> https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-restricted-parameters/

create hook check_licenses_mapping event=queuejob
import hook check_licenses_mapping application/x-python default /opt/soca/%SOCA_CLUSTER_ID/cluster_hooks/queuejob/check_licenses_mapping.py

Note: If you make any change to this file, you MUST re-execute the import command.
If you are installing this file manually, make sure to replace %SOCA_CLUSTER_ID path below
"""

import sys
import sysconfig

# Automatically add SOCA_PYTHON/site-packages to sys.path to allow OpenPBS Hooks to load any custom library installed via SOCA_PYTHON (boto3 ...)
site_packages = sysconfig.get_paths()["purelib"]
if site_packages not in sys.path:
    sys.path.append(site_packages)

import pbs
import yaml

e = pbs.event()
j = e.job

# Validate license_mapping YAML is not malformed
license_settings_file = "/opt/soca/%SOCA_CLUSTER_ID/cluster_manager/orchestrator/settings/licenses_mapping.yml"

try:
    with open(license_settings_file) as f:
        lic_data = yaml.safe_load(f)

    e.accept()

except Exception as err:
    message = f"Job cannot be submitted. Unable to read {license_settings_file}.  Double check the YAML syntax is correct and you don't have any invalid indent.\n Error: {err} "
    e.reject(message)

except SystemExit:
    pass