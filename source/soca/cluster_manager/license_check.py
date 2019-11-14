#!/bin/python
import argparse
import subprocess
import re
import sys
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', nargs='?', required=True,
                        help='FlexLM hostname')
    parser.add_argument('-p', '--port', nargs='?', required=True,
                        help="FlexLM Port")
    parser.add_argument('-f', '--feature', nargs='?', required=True,
                        help="FlexLM Feature")
    parser.add_argument('-m', '--minus', nargs='?',
                        help="Prevent HPC to consume all license by keeping a reserved pool for local usage")

    arg = parser.parse_args()
    lmstat_path = "PATH_TO_LMUTIL"
    if lmstat_path == "PATH_TO_LMUTIL":
        print('Please specify a link to your lmutil binary (edit line 19 of this file')
        sys.exit(1)
    lmstat_cmd = [lmstat_path,'lmstat', '-a', '-c', str(arg.port)+'@'+str(arg.server)]
    grep_cmd = ['grep', "Users of " + str(arg.feature)]

    process_lmstat = subprocess.Popen(lmstat_cmd, stdout=subprocess.PIPE)
    process_grep = subprocess.Popen(grep_cmd, stdin=process_lmstat.stdout, stdout=subprocess.PIPE)
    process_lmstat.stdout.close()
    lmstat = (process_grep.communicate()[0]).decode('utf-8')
    regex_license_in_use = r'.*Total of(.*)licenses? in use.*'
    regex_license_issued = r'.*Total of(.*)licenses? issued;.*'

    try:
        license_in_use = re.search(regex_license_in_use, lmstat,re.MULTILINE).group(1).rstrip().lstrip()
        license_total = re.search(regex_license_issued, lmstat, re.MULTILINE).group(1).rstrip().lstrip()
    except Exception as e:
        print("Error: " +str(e) )
        print("You probably specified license server/port/feature which does not exist")
        sys.exit(1)
    if arg.minus is not None:
        license_total = int(license_total) - int(arg.minus)

    print(int(license_total) - int(license_in_use))
