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

"""
This function is only executed during the first install of your SOCA HPC cluster
This creates a self-signed certificate used by your LoadBalancer.
If a default SOCA certificate is deployed, this script will re-use it and won't create a new one.
This is STRONGLY RECOMMENDED for you to upload your own certificate on ACM and update the Load balancer with your personal/corporate certificate
"""

import boto3
import time
import cfnresponse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import datetime
import logging

client_acm = boto3.client("acm")

logging.getLogger().setLevel(logging.INFO)


def generate_cert(event, context):
    output = {}
    # print(event)
    request_type = event.get("RequestType")
    # print(request_type)
    if request_type == "Delete":
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "Deleting")
        return

    else:
        logging.info("Scanning account for ISSUED certificates...")
        _acm_paginator = client_acm.get_paginator("list_certificates")
        _acm_iterator = _acm_paginator.paginate(CertificateStatuses=["ISSUED"])
        for _page in _acm_iterator:
            for cert in _page.get("CertificateSummaryList", []):
                # print(cert)

                if "SOCA.DEFAULT.CREATE.YOUR.OWN.CERT" == cert.get("DomainName", ""):
                    _cert_arn: str = cert.get("CertificateArn", "")
                    _cert_expire: str = cert.get("NotAfter", "")
                    logging.info(f"Found existing self-signed certificate - ARN {_cert_arn} / Expiration: {_cert_expire}")
                    output["ACMCertificateArn"] = _cert_arn
                    # FIXME TODO - First match wins only - need to compare Tags?
                    break

        #
        # See if we found a valid one from the account
        #
        if "ACMCertificateArn" in output.keys():
            cfnresponse.send(
                event,
                context,
                cfnresponse.SUCCESS,
                output,
                "Using existing Self Signed",
            )
        else:
            #
            # Create a new self-signed cert
            #
            load_balancer_dns_name = event["ResourceProperties"]["LoadBalancerDNSName"]
            cluster_id = event["ResourceProperties"]["ClusterId"]

            one_day = datetime.timedelta(days=1)
            private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
            )
            public_key = private_key.public_key()
            subject = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, 'Sunnyvale'),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, cluster_id),
                    x509.NameAttribute(NameOID.COMMON_NAME, 'SOCA.DEFAULT.CREATE.YOUR.OWN.CERT')
                ]
            )

            certificate = x509.CertificateBuilder() \
                    .subject_name(subject) \
                    .issuer_name(subject) \
                    .not_valid_before(datetime.datetime.today() - one_day) \
                    .not_valid_after(datetime.datetime.today() + (one_day * 3650)) \
                    .serial_number(x509.random_serial_number()) \
                    .public_key(public_key) \
                    .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(load_balancer_dns_name)]), critical=False) \
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
                    .sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

            certificate_content = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            private_key_content = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ).decode("utf-8")

            try:
                # Our base tag
                _tags: list = [
                    {
                        "Key": "Name",
                        "Value": "Soca_ALB_Certificate"
                    }
                ]

                # Custom tags passed to us from the installer
                _custom_tags = event.get("ResourceProperties", {}).get("Tags", [])

                for _tag in _custom_tags:
                    _tag_name: str = _tag.get("Key", "")
                    _tag_value: str = _tag.get("Value", "")
                    if not _tag_name:
                        logging.info(f"Skipping custom tag: {_tag_name}")

                    # user-defined keys can have empty Values so we do not check them

                    logging.debug(f"Adding custom tag: {_tag_name} / Value: {_tag_value}")
                    _tags.append(
                        {
                            "Key": _tag_name,
                            "Value": _tag_value
                        }
                    )

                logging.info(f"All tags for certificate: {_tags}")
                #
                response = client_acm.import_certificate(
                    Certificate=certificate_content,
                    PrivateKey=private_key_content,
                    Tags=_tags,
                )
                time.sleep(30)

                output["ACMCertificateArn"] = response["CertificateArn"]
                cfnresponse.send(
                    event, context, cfnresponse.SUCCESS, output, "Created Self Signed"
                )

            except Exception as e:
                logging.error(f"Error creating self-signed certificate. Cluster may require manual intervention. Error: {e}")
                cfnresponse.send(event, context, cfnresponse.FAILED, output, str(e))
