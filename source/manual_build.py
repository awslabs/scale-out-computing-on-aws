import fileinput
import os
import random
import string
import sys
import boto3
from colored import fg, bg, attr
from botocore.client import ClientError
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

    print("====== Upload to S3 ======\n")
    s3 = boto3.resource('s3')
    region = get_input(" > Please enter the AWS region you'd like to build SOCA in: ")
    bucket_name = get_input(" > Please enter the name of an S3 bucket you own: ")
    try:
        s3.meta.client.head_bucket(Bucket=bucket_name)
    except ClientError:
        bucket_name = input(" > The bucket "+ bucket_name + " does not exist or you have no access.")
    print(" > Uploading required files ... ")
    upload_objects(s3, bucket_name, output_prefix, build_path + "/" + build_folder)

    # CloudFormation Template URL
    template_url = "https://%s.s3.amazonaws.com/%s/scale-out-computing-on-aws.template" % (bucket_name, output_prefix)

    print("\n====== Upload COMPLETE ======")
    print("\n====== Installation Instructions ======")
    print("1. Click on the following link:")
    print("%shttps://console.aws.amazon.com/cloudformation/home?region=%s#/stacks/create/review?&templateURL=%s&param_S3InstallBucket=%s&param_S3InstallFolder=%s%s" % (fg('blue'), region, template_url, bucket_name, output_prefix, attr('reset')))
    print("2. The 'Install Location' parameters are pre-filled for you, fill out the rest of the parameters.")
    print("")
    print("")
    print("For more information: https://awslabs.github.io/scale-out-computing-on-aws/install-soca-cluster/")

    get_input("Press Enter key to close ..")







