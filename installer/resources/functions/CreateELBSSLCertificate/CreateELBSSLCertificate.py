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

def generate_cert(event, context):
    output = {}
    client_acm = boto3.client("acm")
    # print(event)
    request_type = event["RequestType"]
    # print(request_type)
    if event["RequestType"] == "Delete":
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "Deleting")
        return

    else:
        check_existing = client_acm.list_certificates(CertificateStatuses=["ISSUED"])
        for cert in check_existing["CertificateSummaryList"]:
            # print(cert)
            if "SOCA.DEFAULT.CREATE.YOUR.OWN.CERT" == cert["DomainName"]:
                output["ACMCertificateArn"] = cert["CertificateArn"]

        if "ACMCertificateArn" in output.keys():
            cfnresponse.send(
                event,
                context,
                cfnresponse.SUCCESS,
                output,
                "Using existing Self Signed",
            )
        else:
            LoadBalancerDNSName = event["ResourceProperties"]["LoadBalancerDNSName"]
            ClusterId = event["ResourceProperties"]["ClusterId"]

            one_day = datetime.timedelta(1, 0, 0)
            private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend())
            public_key = private_key.public_key()
            subject = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, 'Sunnyvale'),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, ClusterId),
                    x509.NameAttribute(NameOID.COMMON_NAME, 'SOCA.DEFAULT.CREATE.YOUR.OWN.CERT')
            ])

            certificate = x509.CertificateBuilder() \
                    .subject_name(subject) \
                    .issuer_name(subject) \
                    .not_valid_before(datetime.datetime.today() - one_day) \
                    .not_valid_after(datetime.datetime.today() + (one_day * 3650)) \
                    .serial_number(x509.random_serial_number()) \
                    .public_key(public_key) \
                    .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(LoadBalancerDNSName)]), critical=False) \
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
                    .sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

            certificate_content = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            private_key_content = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ).decode("utf-8")

            try:
                response = client_acm.import_certificate(
                    Certificate=certificate_content, PrivateKey=private_key_content
                )
                time.sleep(30)
                output["ACMCertificateArn"] = response["CertificateArn"]
                client_acm.add_tags_to_certificate(
                    CertificateArn=response["CertificateArn"],
                    Tags=[{"Key": "Name", "Value": "Soca_ALB_Certificate"}],
                )
                cfnresponse.send(
                    event, context, cfnresponse.SUCCESS, output, "Created Self Signed"
                )

            except Exception as e:
                cfnresponse.send(event, context, cfnresponse.FAILED, output, str(e))
