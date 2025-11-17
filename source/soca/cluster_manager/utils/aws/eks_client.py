# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from kubernetes import client
from kubernetes.client.rest import ApiException
from kubernetes.client import V1Job, V1JobList, V1Pod, V1PodList
from utils.subprocess_client import SocaSubprocessClient
from utils.aws.boto3_wrapper import get_boto
from utils.http_client import SocaHttpClient
from utils.response import SocaResponse
from utils.error import SocaError
from functools import wraps
import json
import tempfile, base64
from typing import Callable, Optional, Any, Dict, Union
from requests.exceptions import ConnectionError

logger = logging.getLogger("soca_logger")


def k8s_api_wrapper(
    helper_message: str = "An error occurred while calling the Kubernetes API.",
) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self, *args: Any, **kwargs: Any) -> Union[SocaResponse, SocaError]:
            if not self._api_client:
                logger.warning(
                    "Kubernetes client not initialized. Attempting to build."
                )
                build_result = self.build()
                if not build_result.get("success"):
                    logger.error(
                        f"Unable to build Kubernetes client: {build_result.get('message')}"
                    )
                    return SocaError.GENERIC_ERROR(helper=build_result.get("message"))

            try:
                result = func(self, *args, **kwargs)
                return SocaResponse(success=True, message=result)
            except ApiException as e:
                logger.error(f"Kubernetes API exception in {func.__name__}: {e}")
                if e.status in [401, 403]:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unauthorized: Verify if the IAM role can access the cluster '{self.cluster_name}'."
                    )
                else:
                    logger.error(f"Unable to perform operation due to {e}")
                    return SocaError.GENERIC_ERROR(helper=helper_message)
            except Exception as e:
                logger.error(f"Unexpected error in {func.__name__}: {e}")
                return SocaError.GENERIC_ERROR(helper=helper_message)

        return wrapper

    return decorator


class SocaEKSClient:

    def __init__(
        self,
        cluster_name: str,
    ):
        self.cluster_name = cluster_name
        self._eks_client = get_boto(service_name="eks").message
        self._api_server = None
        self._cert_data = None
        self._token = None
        self._api_client = None

    def _get_bearer_token(self) -> Optional[str]:
        command = f"aws eks get-token --cluster-name {self.cluster_name}"
        result = SocaSubprocessClient(run_command=command).run()
        logger.debug(f"_get_bearer_token: {result}")

        if result.get("success"):
            try:
                token = (
                    json.loads(result.get("message")["stdout"])
                    .get("status", {})
                    .get("token")
                )
                return token
            except Exception as e:
                logger.error(f"Error parsing token: {e}")
        else:
            logger.error(f"Failed to get token: {result}")
        return None

    def _describe_cluster(self) -> bool:
        try:
            response = self._eks_client.describe_cluster(name=self.cluster_name)
            cluster = response.get("cluster", {})
            self._api_server = cluster.get("endpoint")
            self._cert_data = cluster.get("certificateAuthority", {}).get("data")
            return True
        except Exception as err:
            logger.error(f"Unable to describe cluster {self.cluster_name}: {err}")
            return False

    def healthcheck(self) -> bool:
        if self._api_server is None:
            self.build()
        health_check = SocaHttpClient(
            endpoint=f"{self._api_server}/healthz", timeout=2
        ).get()
        logger.info(
            f"healthcheck for {self._api_server}/healthz response: {health_check}"
        )
        if health_check.get("success") is False:
            logger.error(f"Cluster unreachable: {health_check}")
            return False
        return True

    def build(self) -> Dict[str, Union[bool, str, client.ApiClient]]:
        logger.info(f"Building Kubernetes client for cluster: {self.cluster_name}")

        if not self._describe_cluster():
            return {"success": False, "message": "Failed to describe cluster."}

        if not self.healthcheck():
            return {
                "success": False,
                "message": "EKS API server is unreachable. Check firewall/security group rules.",
            }

        self._token = self._get_bearer_token()
        if not self._token:
            return {"success": False, "message": "Failed to retrieve bearer token."}

        configuration = client.Configuration()
        configuration.host = self._api_server
        configuration.verify_ssl = True
        configuration.api_key = {"authorization": self._token}
        configuration.api_key_prefix = {"authorization": "Bearer"}
        configuration.timeout = 10

        try:
            ca_cert_bytes = base64.b64decode(self._cert_data)
            ca_file = tempfile.NamedTemporaryFile(delete=False)
            ca_file.write(ca_cert_bytes)
            ca_file.flush()
            configuration.ssl_ca_cert = ca_file.name
        except Exception as e:
            logger.error(f"Failed to write CA certificate: {e}")
            return {"success": False, "message": "Failed to write CA certificate."}

        self._api_client = client.ApiClient(configuration)
        return {"success": True, "message": self._api_client}

    def _get_batch_api(self) -> client.BatchV1Api:
        return client.BatchV1Api(self._api_client)

    def _get_core_api(self) -> client.CoreV1Api:
        return client.CoreV1Api(self._api_client)

    def _get_apps_api(self) -> client.AppsV1Api:
        return client.AppsV1Api(self._api_client)

    # --- Jobs ---
    @k8s_api_wrapper("Unable to read job. See logs for details.")
    def read_namespaced_job(self, name: str, namespace: str) -> V1Job:
        return self._get_batch_api().read_namespaced_job(name=name, namespace=namespace)

    @k8s_api_wrapper("Unable to list job(s). See logs for details.")
    def list_namespaced_job(
        self, namespace: str, label_selector: Optional[str] = None
    ) -> V1JobList:
        return self._get_batch_api().list_namespaced_job(
            namespace=namespace, label_selector=label_selector
        )

    @k8s_api_wrapper("Unable to delete job. See logs for details.")
    def delete_namespaced_job(
        self, name: str, namespace: str, propagation_policy: str = "Foreground"
    ) -> Any:
        return self._get_batch_api().delete_namespaced_job(
            name=name,
            namespace=namespace,
            body=client.V1DeleteOptions(propagation_policy=propagation_policy),
        )

    @k8s_api_wrapper("Unable to create job. See logs for details.")
    def create_namespaced_job(self, body: str, namespace: str) -> V1Job:
        return self._get_batch_api().create_namespaced_job(
            body=body,
            namespace=namespace,
        )

    # --- Pods ---
    @k8s_api_wrapper("Unable to read pod. See logs for details.")
    def read_namespaced_pod(self, name: str, namespace: str) -> V1Pod:
        return self._get_core_api().read_namespaced_pod(name=name, namespace=namespace)

    @k8s_api_wrapper("Unable to list pods. See logs for details.")
    def list_namespaced_pod(
        self, namespace: str, label_selector: Optional[str] = None
    ) -> V1PodList:
        return self._get_core_api().list_namespaced_pod(
            namespace=namespace, label_selector=label_selector
        )

    # --- PodTemplates ---
    @k8s_api_wrapper("Unable to read pod template. See logs for details.")
    def read_namespaced_pod_template(self, name: str, namespace: str):
        return self._get_core_api().read_namespaced_pod_template(
            name=name, namespace=namespace
        )

    @k8s_api_wrapper("Unable to list pod templates. See logs for details.")
    def list_namespaced_pod_template(
        self, namespace: str, label_selector: Optional[str] = None
    ):
        return self._get_core_api().list_namespaced_pod_template(
            namespace=namespace, label_selector=label_selector
        )

    @k8s_api_wrapper("Unable to create pod template. See logs for details.")
    def create_namespaced_pod_template(self, body: dict, namespace: str):
        return self._get_core_api().create_namespaced_pod_template(
            body=body, namespace=namespace
        )

    @k8s_api_wrapper("Unable to delete pod template. See logs for details.")
    def delete_namespaced_pod_template(self, name: str, namespace: str):
        return self._get_core_api().delete_namespaced_pod_template(
            name=name, namespace=namespace, body=client.V1DeleteOptions()
        )

    # --- ReplicaSets ---
    @k8s_api_wrapper("Unable to read ReplicaSet. See logs for details.")
    def read_namespaced_replica_set(self, name: str, namespace: str):
        return self._get_apps_api().read_namespaced_replica_set(
            name=name, namespace=namespace
        )

    @k8s_api_wrapper("Unable to list ReplicaSets. See logs for details.")
    def list_namespaced_replica_set(
        self, namespace: str, label_selector: Optional[str] = None
    ):
        return self._get_apps_api().list_namespaced_replica_set(
            namespace=namespace, label_selector=label_selector
        )

    @k8s_api_wrapper("Unable to create ReplicaSet. See logs for details.")
    def create_namespaced_replica_set(self, body: dict, namespace: str):
        return self._get_apps_api().create_namespaced_replica_set(
            body=body, namespace=namespace
        )

    @k8s_api_wrapper("Unable to delete ReplicaSet. See logs for details.")
    def delete_namespaced_replica_set(self, name: str, namespace: str):
        return self._get_apps_api().delete_namespaced_replica_set(
            name=name, namespace=namespace, body=client.V1DeleteOptions()
        )

    # --- Deployments ---
    @k8s_api_wrapper("Unable to read Deployment. See logs for details.")
    def read_namespaced_deployment(self, name: str, namespace: str):
        return self._get_apps_api().read_namespaced_deployment(
            name=name, namespace=namespace
        )

    @k8s_api_wrapper("Unable to list Deployments. See logs for details.")
    def list_namespaced_deployment(
        self, namespace: str, label_selector: Optional[str] = None
    ):
        return self._get_apps_api().list_namespaced_deployment(
            namespace=namespace, label_selector=label_selector
        )

    @k8s_api_wrapper("Unable to create Deployment. See logs for details.")
    def create_namespaced_deployment(self, body: dict, namespace: str):
        return self._get_apps_api().create_namespaced_deployment(
            body=body, namespace=namespace
        )

    @k8s_api_wrapper("Unable to delete Deployment. See logs for details.")
    def delete_namespaced_deployment(self, name: str, namespace: str):
        return self._get_apps_api().delete_namespaced_deployment(
            name=name, namespace=namespace, body=client.V1DeleteOptions()
        )

    # --- StatefulSets ---
    @k8s_api_wrapper("Unable to read StatefulSet. See logs for details.")
    def read_namespaced_stateful_set(self, name: str, namespace: str):
        return self._get_apps_api().read_namespaced_stateful_set(
            name=name, namespace=namespace
        )

    @k8s_api_wrapper("Unable to list StatefulSets. See logs for details.")
    def list_namespaced_stateful_set(
        self, namespace: str, label_selector: Optional[str] = None
    ):
        return self._get_apps_api().list_namespaced_stateful_set(
            namespace=namespace, label_selector=label_selector
        )

    @k8s_api_wrapper("Unable to create StatefulSet. See logs for details.")
    def create_namespaced_stateful_set(self, body: dict, namespace: str):
        return self._get_apps_api().create_namespaced_stateful_set(
            body=body, namespace=namespace
        )

    @k8s_api_wrapper("Unable to delete StatefulSet. See logs for details.")
    def delete_namespaced_stateful_set(self, name: str, namespace: str):
        return self._get_apps_api().delete_namespaced_stateful_set(
            name=name, namespace=namespace, body=client.V1DeleteOptions()
        )

    # --- DaemonSets ---
    @k8s_api_wrapper("Unable to read DaemonSet. See logs for details.")
    def read_namespaced_daemon_set(self, name: str, namespace: str):
        return self._get_apps_api().read_namespaced_daemon_set(
            name=name, namespace=namespace
        )

    @k8s_api_wrapper("Unable to list DaemonSets. See logs for details.")
    def list_namespaced_daemon_set(
        self, namespace: str, label_selector: Optional[str] = None
    ):
        return self._get_apps_api().list_namespaced_daemon_set(
            namespace=namespace, label_selector=label_selector
        )

    @k8s_api_wrapper("Unable to create DaemonSet. See logs for details.")
    def create_namespaced_daemon_set(self, body: dict, namespace: str):
        return self._get_apps_api().create_namespaced_daemon_set(
            body=body, namespace=namespace
        )

    @k8s_api_wrapper("Unable to delete DaemonSet. See logs for details.")
    def delete_namespaced_daemon_set(self, name: str, namespace: str):
        return self._get_apps_api().delete_namespaced_daemon_set(
            name=name, namespace=namespace, body=client.V1DeleteOptions()
        )
