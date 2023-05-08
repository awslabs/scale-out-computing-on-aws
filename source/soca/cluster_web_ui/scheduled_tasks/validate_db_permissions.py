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
import stat
import logging

logger = logging.getLogger("scheduled_tasks")


def validate_db_permissions():
    # Ensure db.sqlite permissions are always 600
    logger.info(f"validate_db_permissions")
    db_sqlite = os.path.abspath(os.path.dirname(__file__) + "/../db.sqlite")
    check_stat = os.stat(db_sqlite)
    oct_perm = oct(check_stat.st_mode)
    logger.info(
        f"validate_db_permissions: Detected permission {oct_perm} for {db_sqlite} with last 3 digits {oct_perm[-3:]}"
    )
    if oct_perm[-3:] != "600":
        logger.info("validate_db_permissions: Updated permission back to 600")
        os.chmod(db_sqlite, stat.S_IWUSR + stat.S_IRUSR)
