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
# import getpass
from rich import print
from rich.prompt import Prompt, IntPrompt


def get_input(
    prompt,
    specified_value=None,
    expected_answers=None,
    expected_type=int,
    hide=False,
    color="misty_rose_3",
    show_expected_answers=True,
    show_default_answer=True,
):

    if expected_answers is None:
        expected_answers = {}

    # Previous versions of get_input() had expected_answers as list[]
    # Newer get_input() now wants a dict to contain advanced options (visibility)
    # This allows for 'hidden' answers that are acceptable.
    # Default to old behavior if we see an incoming list[] type
    if isinstance(expected_answers, list):
        expected_answers = {
            _answer: {'visible': True} for _answer in expected_answers
        }

    # Don't display if there are over 30 expected answers
    # This may have to be disabled for regions - which we will probably always want a display to the end-user
    if len(expected_answers) > 30:
        show_expected_answers = False

    response = None
    if specified_value:
        # Value specified, validating user provided input
        if expected_answers:
            # Forward lookup
            # print(f"DEBUG - Trying to resolve {specified_value} compared to expected ans: {expected_answers}")
            if specified_value not in expected_answers:
                # print(f"DEBUG - Trying to resolve {specified_value}  to expected ans: {expected_answers} - method2")
                if isinstance(specified_value, str) and isinstance(expected_answers, dict):
                    # print(f"DEBUG - Trying to find {specified_value} in dict - {expected_answers}")

                    # response = next(
                    #     (
                    #         _key
                    #         for _key, _value in expected_answers.items()
                    #         if _value.get('visible', True) and _key.lower() == specified_value
                    #     ),
                    #     None,
                    # )

                    for _key, _value in expected_answers.items():
                        if _value.get('visible', True):
                            if _key.lower() == specified_value.lower():
                                response = _key
                                break

                print(
                    f"[red]{specified_value} is an invalid choice. Valid choices: {', '.join(expected_answers.keys())}[default]"
                )
                sys.exit(1)
        return specified_value

    else:
        # # Value not specified, prompt user
        # while isinstance(response, expected_type) is False:

        # if expected_answers and show_expected_answers:
        #     _ea_string: str = ""
        #     for _potential_answer, _options in expected_answers.items():
        #         _is_answer_visible: bool = _options.get('visible', False)
        #         #print(f"DEBUG - Potential answer: {_potential_answer} - Visible: {_is_answer_visible}")
        #         if _is_answer_visible:
        #             _ea_string += f"{_potential_answer}, "
        #     _ea_string = _ea_string.rstrip(", ")

        # print(f"DEBUG - Asking the question now... ")
        # print(f"DEBUG - Expected answers: {expected_answers}")

        _choices = list(map(str, expected_answers.keys())) if expected_answers else None

        # Determine our default
        _default_choice = _choices[0] if expected_answers else None
        # Scan the expected answers and take the first default
        for _ch in expected_answers:
            if expected_answers[_ch].get('default', False):
                _default_choice = _ch
                break

        # print(f"DEBUG - Choices: {_choices} - Default: {_default_choice}")
        # print(f"DEBUG - Prompt: {prompt}")

        try:
            while True:
                if expected_type is int:
                    response = IntPrompt.ask(
                        prompt=prompt,
                        choices=_choices,
                        default=int(_default_choice) if isinstance(_default_choice, str) else '',
                        show_choices=show_expected_answers,
                        show_default=show_default_answer,
                    )
                    # print(f"DEBUG - Question now: {response}")

                else:
                    response = Prompt.ask(
                        prompt=f"[{color}] >> {prompt}[default]",
                        choices=_choices,
                        default=_default_choice,
                        password=hide,
                        show_choices=show_expected_answers,
                        show_default=show_default_answer,
                    )

                if _choices is None or str(response) in _choices:
                    break
        except Exception as e:
            print(f"Prompt ERROR - {e}")
            sys.exit(1)

    return response
