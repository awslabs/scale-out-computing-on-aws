'''
This hook reject the job if the user does not have a valid budget associated
Doc: https://awslabs.github.io/scale-out-computing-on-aws/analytics/set-up-budget-project/
create hook check_project_budget event=queuejob
import hook check_project_budget application/x-python default /apps/soca/%SOCA_CONFIGURATION/cluster_hooks/queuejob/check_project_budget.py

Note: If you make any change to this file, you MUST re-execute the import command
'''


import sys
import pbs
from configparser import SafeConfigParser  # PBS env is py3.7 or py3.6, so use configparser (instead of ConfigParser in py2.7)
if "/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages" not in sys.path:
    sys.path.append("/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages")
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
        msg = 'Error. Budget file is incorrect: ' + str(ex)
        e.reject(msg)
    return budget_per_project


budget_client = boto3.client('budgets')
e = pbs.event()
j = e.job
job_owner = str(e.requestor)
job_queue = str(j.queue)
job_project = None if j.project is None else str(j.project) # <class 'pbs.v1._base_types.project'> to str

# User Variables
aws_account_id = '<YOUR_AWS_ACCOUNT_ID>'
budget_config_file = '/apps/soca/%SOCA_CONFIGURATION/cluster_manager/settings/project_cost_manager.txt'  # Link to example
user_must_belong_to_project = True  # Change if you don't want to restrict project to a list of users
allow_job_no_project = False  # Change if you do not want to enforce project at job submission
allow_user_multiple_projects = True  # Change if you want to restrict a user to one project

if job_project is None and allow_job_no_project is False:
    msg = 'Error. You tried to submit job without project. Specify project using -P parameter'
    e.reject(msg)

else:
    try:
        pbs.logmsg(pbs.LOG_DEBUG, 'checking_budget: project: ' + str(job_project))
        # Get all budgets
        projects_list = get_all_budgets()

        # Verify user is authorized to use this project
        user_to_project = [key for (key, value) in projects_list.items() if job_owner in value]
        pbs.logmsg(pbs.LOG_DEBUG, 'Budget: user_budget' + str(user_to_project))
        if user_to_project:
            if user_to_project.__len__() > 1 and allow_user_multiple_projects is False:
                msg = 'Error. ' + job_owner + ' has been assigned to more than 1 budget (' + str(user_to_project) + ')'
                e.reject(msg)

            if job_project not in user_to_project:
                msg = 'Error. ' + job_owner + ' is not assigned to project: ' + job_project + ' See ' + budget_config_file
                e.reject(msg)
        else:
            msg = 'User ' + job_owner + ' is not assigned to any project. See ' + budget_config_file
            e.reject(msg)

        # Project is valid and user is authorized. Calculating budget left for project

        try:
            budget_query = budget_client.describe_budget(AccountId=aws_account_id, BudgetName=job_project)
        except Exception as ex:
            msg = 'Error. Unable to query AWS Budget API. ERROR: ' + str(ex)
            e.reject(msg)

        actual_spend = float(budget_query['Budget']['CalculatedSpend']['ActualSpend']['Amount'])
        allocated_budget = float(budget_query['Budget']['BudgetLimit']['Amount'])

        if actual_spend > allocated_budget:
            msg = 'Error. Budget for ' + job_project + ' exceed allocated threshold. Update it on AWS Budget Console'
            e.reject(msg)
        else:
            e.accept()

    except Exception as ex:
        e.reject(str(ex))



