'''
This hook reject the job if the user does not have a valid budget associated

create hook check_user_budget event=queuejob
import hook check_user_budget application/x-python default /apps/pbs/hooks/queuejob/check_user_budget.py
'''

#!/usr/bin/env python

import pbs
import sys

if "/usr/lib/python2.7/site-packages" not in sys.path:
    sys.path.append("/usr/lib/python2.7/site-packages")

if "/usr/lib64/python2.7/site-packages" not in sys.path:
    sys.path.append("/usr/lib64/python2.7/site-packages")

from ConfigParser import SafeConfigParser
import boto3
import os

e = pbs.event()
j = e.job
job_owner = e.requestor
queue = str(j.queue)
aws_account_id = '<YOUR_AWS_ACOUNT_ID>'
config_file = '<PATH_TO_YOUR_CFG_FILE>'

try:
        pbs.logmsg(pbs.LOG_DEBUG, 'Budget: User ' + str(job_owner))
        config = SafeConfigParser(allow_no_value=True)
        budget_list = {}
        try:
            config.read(config_file)
            # Get list of all budget
            #pbs.logmsg(pbs.LOG_DEBUG, 'Budget: section ' + str(config.sections()))
            for section in config.sections():
                budget_list[section] = []
                for account in config.options(section):
                    budget_list[section].append(account)
        except Exception as ex:
            msg = 'Error. Budget file is incorrect: ' + str(ex)
            e.reject(msg)
        #pbs.logmsg(pbs.LOG_DEBUG, 'Budget: budget_list ' + str(budget_list))

        # Find budget for current user
        user_budget = [key for (key, value) in budget_list.items() if job_owner in value]
        pbs.logmsg(pbs.LOG_DEBUG, 'Budget: user_budget' + str(user_budget))

        if user_budget:
            if user_budget.__len__() > 1:
                msg = 'Error. ' + job_owner + ' has been assigned to more than 1 budget (' + str(user_budget) + '). Please cut a ticket https://tiny.amazon.com/upgip6tn/mcrozes-help-ticket to resolve this issue'
                e.reject(msg)

            # Need budgets:ViewBudget IAM policy
            budget_client = boto3.client('budgets')

            try:
                budget_query = budget_client.describe_budget(AccountId=aws_account_id, BudgetName=user_budget[0])
            except Exception as ex:
                msg = 'Error. ' + job_owner + ' seems to be assigned to a budget which is no longer valid. Please cut a ticket: https://tiny.amazon.com/upgip6tn/mcrozes-help-ticket and include the following trace: ' + str(ex)
                e.reject(msg)

            actual_spend = float(budget_query['Budget']['CalculatedSpend']['ActualSpend']['Amount'])
            allocated_budget = float(budget_query['Budget']['BudgetLimit']['Amount'])

            if actual_spend > allocated_budget:
                msg = 'Error. ' + job_owner + ' exceeded his/her allocated budget (' + user_budget[0] + '). Create a ticket: https://tiny.amazon.com/upgip6tn/mcrozes-help-ticket to resolve this issue'
                e.reject(msg)
            else:
                e.accept()
        else:
            msg = 'Error. ' + job_owner + ' does not have a valid budget. Please create a ticket: https://tiny.amazon.com/upgip6tn/mcrozes-help-ticket to resolve this issue'
            e.reject(msg)

except Exception as ex:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        msg = (exc_type, fname, exc_tb.tb_lineno)
        e.reject(str(msg))

