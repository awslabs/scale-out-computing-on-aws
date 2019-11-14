import configparser
import os
import boto3
import os
import json


class RawConfigParser(configparser.RawConfigParser):
    def get(self, section, option):
        val = configparser.RawConfigParser.get(self, section, option)
        return val.strip('"')


def get_parameter(section=False, item=False):
    config = RawConfigParser()
    config.read(os.path.dirname(os.path.realpath(__file__))+'/parameters.cfg')
    if section is False or item is False:
        return 'Please specify both sections and items.'
    else:
        if section in config.keys():
            if item in config[section].keys():
                return config[section][item]
            else:
                return '{} is not a valid item.'.format(item)
        else:
            return '{} is not a valid section.'.format(section)


def get_aligo_configuration():
    secretsmanager_client = boto3.client('secretsmanager')
    configuration_secret_name = os.environ['SOCA_CONFIGURATION']
    response = secretsmanager_client.get_secret_value(SecretId=configuration_secret_name)
    return json.loads(response['SecretString'])

def authorized_dcv_session_count():
    # max number of DCV sessions a user can launch
    return 4
