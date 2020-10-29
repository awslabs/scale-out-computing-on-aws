'''
This hook reject the job if the user is not allowed to use the queue
Doc:
> https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-restricted-parameters/

create hook check_licenses_mapping event=queuejob
import hook check_licenses_mapping application/x-python default /apps/soca/%SOCA_CONFIGURATION/cluster_hooks/queuejob/check_licenses_mapping.py

Note: If you make any change to this file, you MUST re-execute the import command.
If you are installing this file manually, make sure to replace %SOCA_CONFIGURATION path below
'''

import sys
import pbs
if "/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages" not in sys.path:
    sys.path.append("/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages")
import yaml


e = pbs.event()
j = e.job

# Validate license_mapping YAML is not malformed
try:
    license_settings_file = "/apps/soca/%SOCA_CONFIGURATION/cluster_manager/settings/licenses_mapping.yml"
    lic_reader = open(license_settings_file, "r")
    lic_data = yaml.safe_load(lic_reader)
    e.accept()
except Exception as err:
    message = "Job cannot be submitted. Unable to read " + license_settings_file + ". Double chek the YAML syntax is correct and you don't have any invalid indent.\n Error: " + str(err)
    e.reject(message)
