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

from constructs import Construct
import sys
import logging

logger = logging.getLogger("soca_logger")

def get_filesystem_dns(storage_construct: Construct, storage_provider: str, endpoints_suffix: dict, fsx_ontap_junction_path: [str, None]) -> str:
    """
    Retrieve the DNS of the filesystem
    """
    if storage_provider in ("efs", "fsx_lustre"):
        return f"{storage_construct.ref}.{endpoints_suffix[storage_provider]}"
    elif storage_provider == "fsx_ontap":
        # Note: this function is triggered only when SOCA create a brand new FSx for NetApp ONTAP filesystem
        if fsx_ontap_junction_path is None:
            logger.error("fsx_ontap_junction_path is required when storage_provider is fsx_ontap")
            sys.exit(1)
        else:
            return f"{storage_construct.attr_storage_virtual_machine_id}.{storage_construct.file_system_id}.{endpoints_suffix[storage_provider]}:{fsx_ontap_junction_path}"

