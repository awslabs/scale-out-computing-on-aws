# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
This hook reject the job if the user does not have a valid budget associated
Doc: https://awslabs.github.io/scale-out-computing-on-aws/analytics/set-up-budget-project/
"""

from __future__ import annotations
import logging
from configparser import (
    ConfigParser,
)

from utils.response import SocaResponse
from utils.error import SocaError
from utils.config import SocaConfig
from utils.aws.boto3_wrapper import get_boto

logger = logging.getLogger("soca_logger")

budget_client = get_boto(service_name="budgets").message


def main(
    obj: "SocaHpcHooksValidator",
    allow_job_no_project: bool = False,
    allow_user_multiple_projects: bool = True,
) -> SocaResponse | SocaError:
    """
    allow_job_no_project: Set to true if you do not want to enforce a project for all jobs and want to allow jobs without a project. This is useful when you only want to enforce budget checks for specific jobs rather than all of them.
    allow_user_multiple_projects: Change if you want to restrict a user to a single project
    """
    logger.info(
        f"Validating Budget Hook with {obj.job_project=} / {obj.job_owner=} {allow_job_no_project=} / {allow_user_multiple_projects=}"
    )

    if obj.job_project is None:
        if allow_job_no_project is False:
            return SocaError.GENERIC_ERROR(
                helper=f"You tried to submit job without project. Specify project using -P parameter (PBS) or --project"
            )
        else:
            return SocaResponse(
                success=True,
                message="No project specified but allow_job_no_project is enabled",
            )

    config = ConfigParser(allow_no_value=True)

    _budget_per_project = {}
    try:
        config.read(obj.budget_config_file)
        # Get list of all budget
        for section in config.sections():
            _budget_per_project[section] = []
            for account in config.options(section):
                _budget_per_project[section].append(account)
    except Exception as ex:
        return SocaError.GENERIC_ERROR(helper=f"Budget file is incorrect: {ex}")

    logger.debug(f"Found all project/budget: {_budget_per_project}")

    # Verify user is authorized to use this project
    user_to_project = [
        key for (key, value) in _budget_per_project.items() if obj.job_owner in value
    ]
    logger.debug(
        f"{obj.job_owner} belongs to the following project/budget: {user_to_project}"
    )
    if user_to_project:
        if len(user_to_project) > 1 and allow_user_multiple_projects is False:
            return SocaError.GENERIC_ERROR(
                helper=f"{obj.job_owner} has been assigned to more than 1 budget {str(user_to_project)}"
            )

        if obj.job_project not in user_to_project:
            return SocaError.GENERIC_ERROR(
                helper=f"Error {obj.job_owner} is not assigned to project: {str(obj.job_project)}. Please check {obj.budget_config_file}"
            )

    else:
        return SocaError.GENERIC_ERROR(
            helper=f"Error {obj.job_owner} is not assigned to any project. Please check {obj.budget_config_file}"
        )

    # Project is valid and user is authorized. Calculating budget left for project
    _fetch_aws_account_id = SocaConfig(key="/configuration/AWSAccountId").get_value()
    if _fetch_aws_account_id.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to retrieve AWS Account ID due to {str(_fetch_aws_account_id)}"
        )
    else:
        _account_id = _fetch_aws_account_id.get("message")

    logger.debug(f"Found AWS Account ID {_account_id}")
    try:
        _budget_query = budget_client.describe_budget(
            AccountId=_account_id, BudgetName=obj.job_project
        )
    except Exception as ex:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to query AWS Budget API due to {ex}"
        )

    logger.debug(f"Found valid budget {obj.job_project} with data {_budget_query}")
    try:
        _actual_spend = float(
            _budget_query["Budget"]["CalculatedSpend"]["ActualSpend"]["Amount"]
        )
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to retrieve CalculatedSpend.ActualSpend from AWS Budget API due to {err}"
        )

    try:
        _allocated_budget = float(_budget_query["Budget"]["BudgetLimit"]["Amount"])
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to retrieve BudgetLimit from AWS Budget API due to {err}"
        )

    if _actual_spend > _allocated_budget:
        return SocaError.GENERIC_ERROR(
            helper=f"Budget for {obj.job_project} exceed allocated threshold. Update it on AWS Budget Console"
        )
    else:
        return SocaResponse(success=True, message="Validated budget")
