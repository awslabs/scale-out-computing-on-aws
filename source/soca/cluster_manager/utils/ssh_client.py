# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import paramiko
import os
from utils.error import SocaError
import logging
from typing import Optional, Literal
from utils.response import SocaResponse
import pathlib

logger = logging.getLogger("soca_logger")


class SocaSSHClient:
    """
    A utility class for SSH and SCP operations using Paramiko.
    Supports:
      - Connecting via private key
      - Executing commands
      - Uploading and downloading files

    # Example usage:
    ssh = SSHClient("192.168.1.10", "socaadmin", "/data/home/socaadmin/.ssh/id_rsa")
    ssh.connect()

    _execute_cmd = ssh.execute("uname -a")
    if _execute_cmd.get("success") is True:
        print("Output:", _execute_cmd.get("message"))

    ssh.upload("local_file.txt", "/tmp/remote_file.txt")
    ssh.download("/tmp/remote_file.txt", "downloaded_file.txt")
    ssh.close()
    """

    def __init__(self, hostname: str, username: str, key_path: str, port: int = 22):
        self._hostname = hostname
        self._username = username
        self._key_path = key_path
        self._port = port
        self._client = None
        self._sftp = None

    def connect(self) -> SocaResponse:
        """Establish SSH connection."""
        try:
            if not pathlib.Path(self._key_path).exists():
                return SocaError.GENERIC_ERROR(
                    helper=f"Key path {self._key_path} does not exist"
                )

            key = paramiko.RSAKey.from_private_key_file(self._key_path)
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=self._hostname,
                port=self._port,
                username=self._username,
                pkey=key,
                timeout=10,
            )
            self.sftp = self.client.open_sftp()
            return SocaResponse(
                success=True, message=f"SSH connection established to  {self._hostname}"
            )
        except Exception as e:
            return SocaError.GENERIC_ERROR(helper=f"SSH connection failed due to {e}")

    def execute(self, command: str) -> SocaResponse:
        """Execute a command on the remote host and return stdout, stderr, exit_code."""
        if not self.client:
            return SocaError.GENERIC_ERROR(
                helper="SSH connection not established. call connect() first"
            )

        _stdin, _stdout, _stderr = self.client.exec_command(command)
        _exit_code = _stdout.channel.recv_exit_status()
        return SocaResponse(
            success=True,
            message={
                "stdout": _stdout.read().decode(),
                "stderr": _stderr.read().decode(),
                "exit_code": _exit_code,
            },
        )

    def upload(self, local_path, remote_path) -> SocaResponse:
        """Upload a file to the remote host."""
        if not self.sftp:
            return SocaError.GENERIC_ERROR(helper="SFTP session not established.")

        try:
            self.sftp.put(local_path, remote_path)
            return SocaResponse(
                success=True, message=f"Uploaded {local_path} to {remote_path}"
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to upload {local_path} to {remote_path} due to {err}"
            )

    def download(self, remote_path, local_path) -> SocaResponse:
        """Download a file from the remote host."""
        if not self.sftp:
            return SocaError.GENERIC_ERROR(helper="SFTP session not established.")
        try:
            self.sftp.get(remote_path, local_path)
            return SocaResponse(
                success=True, message=f"Downloaded {remote_path} to {local_path}"
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to download {remote_path} to {local_path} due to {err}"
            )

    def close(self):
        """Close SSH and SFTP connections."""
        if self.sftp:
            self.sftp.close()
        if self.client:
            self.client.close()
        logger.info("SSH/SFTP Connection closed.")
