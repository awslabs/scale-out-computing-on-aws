"""
This function is only executed during the first install of your SOCA HPC cluster
This creates a self-signed certificate used by your LoadBalancer.
If a default SOCA certificate is deployed, this script will re-use it and won't create a new one.
This is STRONGLY RECOMMENDED for you to upload your own certificate on ACM and update the Load balancer with your personal/corporate certificate
"""

import boto3
import subprocess
import time
import cfnresponse

def generate_cert(event, context):
    output = {}
    client_acm = boto3.client('acm')
    #print(event)
    request_type = event['RequestType']
    #print(request_type)
    if event['RequestType'] == 'Delete':
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, 'Deleting')
        return

    else:
        check_existing = client_acm.list_certificates(CertificateStatuses=['ISSUED'])
        for cert in check_existing['CertificateSummaryList']:
            #print(cert)
            if 'SOCA.DEFAULT.CREATE.YOUR.OWN.CERT' == cert['DomainName']:
                output['ACMCertificateArn'] = cert['CertificateArn']

        if 'ACMCertificateArn' in output.keys():
          cfnresponse.send(event, context, cfnresponse.SUCCESS, output, 'Using existing Self Signed')
        else:
          LoadBalancerDNSName = event['ResourceProperties']['LoadBalancerDNSName']
          ClusterId = event['ResourceProperties']['ClusterId']
          subprocess.check_output("openssl genrsa 2048 > /tmp/server.key", shell=True)
          subprocess.check_output("openssl req -new -x509 -sha1 -nodes -days 3650  -key /tmp/server.key -subj '/C=US/ST=California/L=Sunnyvale/O="+ClusterId+"/CN=SOCA.DEFAULT.CREATE.YOUR.OWN.CERT' > /tmp/server.crt", shell=True) # nosec
          key = (open("/tmp/server.key","r")).read()  # nosec
          crt = (open("/tmp/server.crt","r")).read()  # nosec

          try:
            response = client_acm.import_certificate(Certificate=crt, PrivateKey=key)
            time.sleep(30)
            output['ACMCertificateArn'] = response['CertificateArn']
            client_acm.add_tags_to_certificate(
      CertificateArn=response['CertificateArn'],
      Tags=[
        {
          'Key': 'Name',
          'Value': 'Soca_ALB_Cerficate'
         }
            ])
            cfnresponse.send(event, context, cfnresponse.SUCCESS, output, 'Created Self Signed')

          except Exception as e:
            cfnresponse.send(event, context, cfnresponse.FAILED, output, str(e))
