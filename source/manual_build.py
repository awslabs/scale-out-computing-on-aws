import fileinput
import os
import random
import string
import sys
import argparse
from shutil import make_archive, copy, copytree

def upload_objects(s3, bucket_name, s3_prefix, directory_name):
    try:
        my_bucket = s3.Bucket(bucket_name)
        for path, subdirs, files in os.walk(directory_name):
            path = path.replace("\\","/")
            directory = path.replace(directory_name,"")
            for file in files:
                print("%s[+] Uploading %s to s3://%s/%s%s%s" % (fg('green'), os.path.join(path, file), bucket_name, s3_prefix, directory+'/'+file, attr('reset')))
                my_bucket.upload_file(os.path.join(path, file), s3_prefix+directory+'/'+file)

    except Exception as err:
        print(err)


def get_input(prompt):
    if sys.version_info[0] >= 3:
        response = input(prompt)
    else:
        #Python 2
        response = raw_input(prompt)
    return response

if __name__ == "__main__":
    try:
        from colored import fg, bg, attr
        import boto3
        from requests import get
        from botocore.client import ClientError
        from botocore.exceptions import ProfileNotFound
    except ImportError:
        print(" > You must have 'colored', 'boto3' and 'requests' installed. Run 'pip install boto3 colored requests'")
        exit(1)

    parser = argparse.ArgumentParser(description='Build & Upload SOCA CloudFormation resources.')
    parser.add_argument('--profile', '-p', type=str, help='AWS CLI profile to use. See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html')
    parser.add_argument('--region', '-r', type=str, help='AWS region to use. If not specified will be prompted.')
    parser.add_argument('--bucket', '-b', type=str, help='S3 Bucket to use. If not specified will be prompted.')
    args = parser.parse_args()

    print("====== Parameters ======\n")
    if not args.region:
        region = get_input(" > Please enter the AWS region you'd like to build SOCA in: ")
    else:
        region = args.region
    if not args.bucket:
        bucket = get_input(" > Please enter the name of an S3 bucket you own: ")
    else:
        bucket = args.bucket

    s3_bucket_exists = False
    try:
        print(" > Validating you can have access to that bucket...")
        if args.profile:
            try:
                session = boto3.session.Session(profile_name=args.profile)
                s3 = session.resource('s3', region_name=region)
            except ProfileNotFound:
                print(" > Profile %s not found. Check ~/.aws/credentials file." % args.profile)
                exit(1)
        else:
            s3 = boto3.resource('s3', region_name=region)
        s3.meta.client.head_bucket(Bucket=bucket)
        s3_bucket_exists = True
    except ClientError as e:
        print(" > The bucket "+ bucket + " does not exist or you have no access.")
        print(e)
        print(" > Building locally but not uploading to S3")

    # Detect Client IP
    get_client_ip = get("https://ifconfig.co/json")
    if get_client_ip.status_code == 200:
        client_ip = get_client_ip.json()['ip'] + '/32'
    else:
        client_ip = ''

    build_path = os.path.dirname(os.path.realpath(__file__))
    os.chdir(build_path)
    # Make sure build ID is > 3 chars and does not start with a number
    unique_id = ''.join(random.choice(string.ascii_lowercase) + random.choice(string.digits) for i in range(2))
    build_folder = 'dist/' + unique_id
    output_prefix = "soca-installer-" + unique_id  # prefix for the output artifact
    print("====== SOCA Build ======\n")
    print(" > Generated unique ID for build: " + unique_id)
    print(" > Creating temporary build folder ... ")
    print(" > Copying required files ... ")
    targets = ['scripts', 'templates', 'README.txt', 'scale-out-computing-on-aws.template', 'install-with-existing-resources.template']
    for target in targets:
        if os.path.isdir(target):
            copytree(target, build_folder + '/' + target)
        else:
            copy(target, build_folder + '/' + target)
    make_archive(build_folder + '/soca', 'gztar', 'soca')

    # Replace Placeholder
    for line in fileinput.input([build_folder + '/scale-out-computing-on-aws.template', build_folder + '/install-with-existing-resources.template'], inplace=True):
        print(line.replace('%%BUCKET_NAME%%', 'your-s3-bucket-name-here').replace('%%SOLUTION_NAME%%/%%VERSION%%', 'your-s3-folder-name-here').replace('\n', ''))

    print(" > Creating archive for build id: " + unique_id)
    make_archive('dist/' + output_prefix, 'gztar', build_folder)



    if s3_bucket_exists:
        print("====== Upload to S3 ======\n")
        print(" > Uploading required files ... ")
        upload_objects(s3, bucket, output_prefix, build_path + "/" + build_folder)

        # CloudFormation Template URL
        template_url = "https://%s.s3.amazonaws.com/%s/scale-out-computing-on-aws.template" % (bucket, output_prefix)

        print("\n====== Upload COMPLETE ======")
        print("\n====== Installation Instructions ======")
        print("1. Click on the following link:")
        print("%s==> https://console.aws.amazon.com/cloudformation/home?region=%s#/stacks/create/review?&templateURL=%s&param_S3InstallBucket=%s&param_ClientIp=%s&param_S3InstallFolder=%s%s" % (fg('light_blue'), region, template_url, bucket, client_ip, output_prefix, attr('reset')))
        print("2. The 'Install Location' parameters are pre-filled for you, fill out the rest of the parameters.")
    else:
        print("\n====== Installation Instructions ======")
        print("1: Create or use an existing S3 bucket on your AWS account (eg: 'mysocacluster')")
        print("2: Drag & Drop " + build_path + "/" + build_folder + " to your S3 bucket (eg: 'mysocacluster/" + build_folder + ")")
        print("3: Launch CloudFormation and use scale-out-computing-on-aws.template as base template")
        print("4: Enter your cluster information.")

    print("\n\nFor more information: https://awslabs.github.io/scale-out-computing-on-aws/install-soca-cluster/")








