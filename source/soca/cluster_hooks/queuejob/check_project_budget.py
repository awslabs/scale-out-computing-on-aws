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
This hook reject the job if the user does not have a valid budget associated
Doc: https://awslabs.github.io/scale-out-computing-on-aws/analytics/set-up-budget-project/
create hook check_project_budget event=queuejob
import hook check_project_budget application/x-python default /opt/soca/%SOCA_CLUSTER_ID/cluster_hooks/queuejob/check_project_budget.py

Note: If you make any change to this file, you MUST re-execute the import command
"""

import sys
import sysconfig

# Automatically add SOCA_PYTHON/site-packages to sys.path to allow OpenPBS Hooks to load any custom library installed via SOCA_PYTHON (boto3 ...)
site_packages = sysconfig.get_paths()["purelib"]
if site_packages not in sys.path:
    sys.path.append(site_packages)

import pbs
from configparser import (
    SafeConfigParser,
)

import boto3


def get_all_budgets():
    config = SafeConfigParser(allow_no_value=True)
    budget_per_project = {}
    try:
        config.read(budget_config_file)
        # Get list of all budget
        for section in config.sections():
            budget_per_project[section] = []
            for account in config.options(section):
                budget_per_project[section].append(account)
    except Exception as ex:
        e.reject(f"Error. Budget file is incorrect: {ex}")

    return budget_per_project


budget_client = boto3.client("budgets")
e = pbs.event()
j = e.job
job_owner = str(e.requestor)
job_queue = str(j.queue)
job_project = (
    None if j.project is None else str(j.project)
)  # <class 'pbs.v1._base_types.project'> to str

# User Variables
aws_account_id = "<YOUR_AWS_ACCOUNT_ID>"
budget_config_file = "/opt/soca/%SOCA_CLUSTER_ID/cluster_manager/orchestrator/settings/project_cost_manager.txt"  # Link to example
user_must_belong_to_project = (
    True  # Change if you don't want to restrict project to a list of users
)
allow_job_no_project = (
    False  # Change if you do not want to enforce project at job submission
)
allow_user_multiple_projects = (
    True  # Change if you want to restrict a user to one project
)

if job_project is None and allow_job_no_project is False:
    e.reject(
        "Error. You tried to submit job without project. Specify project using -P parameter"
    )

else:
    try:
        pbs.logmsg(pbs.LOG_DEBUG, f"checking_budget: project: {job_project}")
        # Get all budgets
        projects_list = get_all_budgets()

        # Verify user is authorized to use this project
        user_to_project = [
            key for (key, value) in projects_list.items() if job_owner in value
        ]
        pbs.logmsg(pbs.LOG_DEBUG, f"Budget: user_budget {user_to_project}")
        if user_to_project:
            if user_to_project.__len__() > 1 and allow_user_multiple_projects is False:
                e.reject(
                    f"Error {job_owner} has been assigned to more than 1 budget {str(user_to_project)}"
                )

            if job_project not in user_to_project:
                e.reject(
                    f"Error {job_owner}  is not assigned to project: {str(job_project)}. Please check {budget_config_file}"
                )
        else:
            e.reject(
                f"Error {job_owner}  is not assigned to any project. Please check {budget_config_file}"
            )

        # Project is valid and user is authorized. Calculating budget left for project

        try:
            budget_query = budget_client.describe_budget(
                AccountId=aws_account_id, BudgetName=job_project
            )
        except Exception as ex:
            e.reject(f"Error. Unable to query AWS Budget API. ERROR: {ex}")

        actual_spend = float(
            budget_query["Budget"]["CalculatedSpend"]["ActualSpend"]["Amount"]
        )
        allocated_budget = float(budget_query["Budget"]["BudgetLimit"]["Amount"])

        if actual_spend > allocated_budget:
            e.reject(
                f"Error. Budget for {job_project} exceed allocated threshold. Update it on AWS Budget Console"
            )
        else:
            e.accept()

    except Exception as ex:
        e.reject(str(ex))
