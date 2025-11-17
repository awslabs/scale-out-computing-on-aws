# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import re
from typing import Optional
from utils.response import SocaResponse
from utils.subprocess_client import SocaSubprocessClient
from utils.error import SocaError
from utils.cast import SocaCastEngine
import pathlib
import argparse
import os

logger = logging.getLogger("soca_logger")


class SocaLicenseQuery:

    def __init__(
        self,
        server: str,  # license endpoint
        port: int,  # license port
        feature: str,  # feature to check
        minus: Optional[
            int
        ] = 0,  # Prevent HPC to consume all license by keeping a reserved pool for local usage
    ):

        self._server = server
        self._port = port
        self._feature = feature
        self._minus = minus

    def flexlm(self, lmutil_path: Optional[str] = None):
        # Check if SOCA_LMUTIL_PATH environment exist with a path to your lmutil, otherwise fallback to the path specified below
        # eg: LMUTIL_PATH = os.environ.get("SOCA_LMUTIL_PATH", "/apps/flexlm/bin/lmutil")
        if lmutil_path is None:
            logger.info(
                "lmutil_path not specified, checking if SOCA_LMUTIL_PATH env variable exist"
            )
            if (lmutil_path := os.environ.get("SOCA_LMUTIL_PATH", None)) is None:
                return SocaError.GENERIC_ERROR(
                    helper="Unable to find lmutil binary, SOCA_LMUTIL_PATH environment variable not set",
                )

        if pathlib.Path(lmutil_path).exists() is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to find lmutil binary, {lmutil_path} does not seems to exisst",
            )

        _lmstat_output = SocaSubprocessClient(
            run_command=f"{lmutil_path} lmstat -a -c {self._port}@{self._server} -f {self._feature}"
        ).run()

        if _lmstat_output.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to run lmstat {_lmstat_output.get('message')}"
            )

        else:
            _output = _lmstat_output.get("message").get("stdout")
            _regex_license_in_use = re.search(
                r".*Total of(.*)licenses? in use.*", _output, re.MULTILINE
            )
            _regex_license_issued = re.search(
                r".*Total of(.*)licenses? issued;.*", _output, re.MULTILINE
            )

            if _regex_license_in_use:
                if (
                    _licenses_in_use := SocaCastEngine(
                        data=_regex_license_in_use.group(1).strip()
                    ).cast_as(int)
                ).get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to parse lmstat output {_output} for {_regex_license_in_use=}. Error {_licenses_in_use.get('message')}"
                    )
                else:
                    _licenses_in_use = _licenses_in_use.get("message")
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to parse lmstat output {_output} for {_regex_license_in_use=}"
                )

            if _regex_license_issued:
                if (
                    _licenses_issued := SocaCastEngine(
                        data=_regex_license_issued.group(1).strip()
                    ).cast_as(int)
                ).get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to parse lmstat output {_output} for {_regex_license_issued=}. Error {_licenses_issued.get('message')}"
                    )
                else:
                    _licenses_in_use = _licenses_in_use.get("message")
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to parse lmstat output {_output} for {_regex_license_in_use=}"
                )

            if self._minus is not None:
                _licenses_issued = _licenses_issued - self._minus

            return SocaResponse(
                success=True, message=_licenses_issued - _licenses_in_use
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s", "--server", nargs="?", required=True, help="FlexLM hostname"
    )
    parser.add_argument("-p", "--port", nargs="?", required=True, help="FlexLM Port")
    parser.add_argument(
        "-f", "--feature", nargs="?", required=True, help="FlexLM Feature"
    )
    parser.add_argument(
        "-m",
        "--minus",
        nargs="?",
        help="Prevent HPC to consume all license by keeping a reserved pool for local usage",
    )

    args = parser.parse_args()
    _get_license = SocaLicenseQuery(
        server=args.server, port=args.port, feature=args.feature, minus=args.minus
    ).flexlm()

    print(_get_license.get("message"))
