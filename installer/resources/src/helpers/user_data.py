# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re

def remove_text(text_to_remove: list, data: str) -> str:
    _user_data = data
    for _t in text_to_remove:
        _user_data = re.sub(f"{_t}", "", _user_data, flags=re.IGNORECASE)

    # Remove leading spaces
    _user_data =  re.sub(r"^[ \t]+", "", _user_data, flags=re.MULTILINE)

    # Remove comments
    _user_data = re.sub(r"^(?!#!)(#.*)$", "", _user_data, flags=re.MULTILINE)

    # Finally remove blank lines
    _user_data = re.sub(r"^\s*\n", "", _user_data, flags=re.MULTILINE)

    return _user_data