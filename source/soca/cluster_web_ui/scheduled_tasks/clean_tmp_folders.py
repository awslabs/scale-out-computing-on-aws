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

import os
import glob
import logging

logger = logging.getLogger("api_log")


def clean_tmp_folders():
    directories = ["tmp/zip_downloads/*", "tmp/ssh/*"]
    for directory in directories:
        logger.info(f"Removing files inside {directory}")
        files = glob.glob(directory)
        for f in files:
            logger.info(f"Removing {f}")
            os.remove(f)
