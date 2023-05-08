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

import sys
from colored import fg, bg, attr
import getpass


def get_input(
    prompt,
    specified_value=None,
    expected_answers=None,
    expected_type=int,
    hide=False,
    color="misty_rose_3",
):
    if expected_answers is None:
        expected_answers = []
    response = None
    if specified_value:
        # Value specified, validating user provided input
        if expected_answers:
            if specified_value not in expected_answers:
                print(
                    f"{fg('red')}{specified_value} is an invalid choice. Choose something from {expected_answers}{attr('reset')}"
                )
                sys.exit(1)
        return specified_value

    else:
        # Value not specified, prompt user
        while isinstance(response, expected_type) is False:
            if sys.version_info[0] >= 3:
                if expected_answers:
                    question = input(
                        f"{fg(color)} >> {prompt} {expected_answers}{attr('reset')}: "
                    )
                else:
                    if hide is True:
                        question = getpass.getpass(
                            prompt=f"{fg(color)} >> {prompt}{attr('reset')}: "
                        )
                    else:
                        question = input(f"{fg(color)} >> {prompt}{attr('reset')}: ")
            else:
                # Python 2
                if expected_answers:
                    question = raw_input(
                        f"{fg(color)} >> {prompt} {expected_answers}{attr('reset')}: "
                    )
                else:
                    question = raw_input(f"{fg(color)} >> {prompt}{attr('reset')}: ")

            try:
                response = expected_type(question.rstrip().lstrip())
            except ValueError:
                print(f"Sorry, expected answer is something from {expected_answers}")

            if expected_answers:
                if response not in expected_answers:
                    print(
                        f"{fg('red')}{response} is an invalid choice. Choose something from {expected_answers}{attr('reset')}"
                    )
                    response = None

    return response
