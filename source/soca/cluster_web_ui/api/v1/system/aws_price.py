from flask_restful import Resource, reqparse
import logging
import boto3
import ast
import re
import math

logger = logging.getLogger("api")


def get_compute_pricing(ec2_instance_type):
    pricing = {}
    region_mapping = {"ap-east-1": "APE1-",
                      "ap-northeast-1": "APN1-",
                      "ap-northeast-2": "APN2-",
                      "ap-south-1": "APS1-",
                      "ap-southeast-1": "APS1-",
                      "ap-southeast-2": "APS1-",
                      "ca-central-1": "CAC1-",
                      "eu-central-1":  "EUC1-",
                      "eu-north-1": "EUN1-",
                      "eu-south-1": "EUS1-",
                      "eu-west-1":  "EUW1-",
                      "eu-west-2":  "EUW2-",
                      "eu-west-3":  "EUW3-",
                      "me-south-1":  "MES1-",
                      "us-east-1":  "",
                      "us-east-2":  "USE2-",
                      "us-west-1":  "USW1-",
                      "us-west-2":  "USW2-",
                      "sa-east-1":  "SAE1-",
    }
    client_pricing = boto3.client("pricing", region_name="us-east-1")
    session = boto3.session.Session()
    region = session.region_name
    response = client_pricing.get_products(
        ServiceCode='AmazonEC2',
        Filters=[
            {
                'Type': 'TERM_MATCH',
                'Field': 'usageType',
                'Value': region_mapping[region] + 'BoxUsage:' + ec2_instance_type
            },
        ],

    )
    for data in response['PriceList']:
        data = ast.literal_eval(data)
        for k, v in data['terms'].items():
            if k == 'OnDemand':
                for skus in v.keys():
                    for ratecode in v[skus]['priceDimensions'].keys():
                        instance_data = v[skus]['priceDimensions'][ratecode]
                        if 'on demand linux ' + str(ec2_instance_type) + ' instance hour' in instance_data['description'].lower():
                            pricing['ondemand'] = float(instance_data['pricePerUnit']['USD'])
            else:
                for skus in v.keys():
                    if v[skus]['termAttributes']['OfferingClass'] == 'standard' \
                            and v[skus]['termAttributes']['LeaseContractLength'] == '1yr' \
                            and v[skus]['termAttributes']['PurchaseOption'] == 'No Upfront':
                        for ratecode in v[skus]['priceDimensions'].keys():
                            instance_data = v[skus]['priceDimensions'][ratecode]
                            if 'Linux/UNIX (Amazon VPC)' in instance_data['description']:
                                pricing['reserved'] = float(instance_data['pricePerUnit']['USD'])
    return pricing


def compute(instance_type, walltime, nodect):
    compute_data = {}
    if instance_type:
        compute_price = get_compute_pricing(instance_type)

    compute_data["on_demand_hourly_rate"] = "%.3f" % compute_price["ondemand"]
    compute_data["reserved_hourly_rate"] = "%.3f" % compute_price["reserved"]
    compute_data["nodes"] = nodect
    compute_data["walltime"] = "%.3f" % walltime
    compute_data["instance_type"] = instance_type
    compute_data["estimated_on_demand_cost"] = "%.3f" % ((compute_price["ondemand"] * nodect) * walltime)
    compute_data["estimated_reserved_cost"] = "%.3f" % ((compute_price["reserved"] * nodect) * walltime)
    return compute_data

class AwsPrice(Resource):
    def get(self):
        """
        Return RI/OD price based on compute/storage inputs
        ---
        tags:
          - AWS
        responses:
          200:
            description: Pair of user/token is valid
          203:
            description: Invalid user/token pair
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument('instance_type', type=str, location='args')
        parser.add_argument('wall_time', type=str, location='args', help="Please specify wall_time using HH:MM:SS format", default="01:00:00")
        parser.add_argument('cpus', type=int, location='args', help="Please specify how many cpus you want to allocate")
        parser.add_argument('scratch_size', type=int, location='args', help="Please specify storage in GB to allocate to /scratch partition (Default 0)", default=0)
        parser.add_argument('root_size', type=int, location='args', help="Please specify your AMI root disk space (Default 10gb)", default=10)
        parser.add_argument('fsx_capacity', type=int, location='args', help="Please specify fsx_storage in GB", default=0)
        parser.add_argument('fsx_type', type=str, location='args', default="SCRATCH_2")
        args = parser.parse_args()
        instance_type = args['instance_type']
        scratch_size = args['scratch_size']
        root_size = args['root_size']
        fsx_storage = args['fsx_capacity']
        fsx_type = args['fsx_type']
        cpus = args['cpus']
        sim_cost = {}

        # Change value below as needed if you use a different region
        EBS_GP2_STORAGE_BASELINE = 0.1  # us-east-1 0.1 cts per gb per month
        FSX_STORAGE_BASELINE = 0.14  # us-east-1Persistent (50 MB/s/TiB baseline, up to 1.3 GB/s/TiB burst)  Scratch (200 MB/s/TiB baseline, up to 1.3 GB/s/TiB burst)

        # Get WallTime in hours
        wall_time_unformated = args['wall_time'].split(":")
        if wall_time_unformated.__len__() != 3:
            return {"message": "wall_time must use HH:MM:SS format. For example 90 minutes will be 00:90:00 or 01:30:00"}, 500
        try:
            sim_hours = float(wall_time_unformated[0]) if wall_time_unformated[0] != "00" else 0.000
            sim_minutes = float(wall_time_unformated[1]) if wall_time_unformated[1] != "00" else 0.000
            sim_seconds = float(wall_time_unformated[2]) if wall_time_unformated[2] != "00" else 0.000
        except ValueError:
            return {"message": "wall_time must use HH:MM:SS and only use numbers"}, 500

        walltime = sim_hours + (sim_minutes / 60) + (sim_seconds / 3600)

        # Calculate number of nodes required based on instance type and CPUs requested
        if cpus is None:
            nodect = 1
        else:
            cpus_count_pattern = re.search(r'[.](\d+)', instance_type)
            if cpus_count_pattern:
                cpu_per_system = int(cpus_count_pattern.group(1)) * 2
            else:
                cpu_per_system = 2
            nodect = math.ceil(int(cpus) / cpu_per_system)

        # Calculate EBS Storage (storage * ebs_price * sim_time_in_secs / (walltime_seconds * 30 days) * number of nodes
        sim_cost["scratch_size"] = "%.3f" % ((scratch_size * EBS_GP2_STORAGE_BASELINE * (walltime * 3600) / (86400 * 30)) * nodect)
        sim_cost["root_size"] = "%.3f" % ((root_size * EBS_GP2_STORAGE_BASELINE * (walltime * 3600) / (86400 * 30)) * nodect)

        # Calculate FSx Storage (storage * fsx_price * sim_time_in_secs / (second_in_a_day * 30 days)
        sim_cost["fsx_capacity"] = "%.3f" % (fsx_storage * FSX_STORAGE_BASELINE * (walltime * 3600) / (86400 * 30))
        # Calculate Compute
        try:
            sim_cost["compute"] = compute(instance_type, walltime, nodect)
        except Exception as err:
            sim_cost["compute"] = {"message": "Unable to get compute price. Instance type may be incorrect or region name not tracked correctly? Error: " +str(err)}
            return sim_cost, 500

        # Output
        sim_cost["estimated_storage_cost"] = "%.3f" % (float(sim_cost["fsx_capacity"]) + float(sim_cost["scratch_size"]) + float(sim_cost["root_size"]))
        sim_cost["estimated_total_cost"] = "%.3f" % (float(sim_cost["estimated_storage_cost"]) + float(sim_cost["compute"]["estimated_on_demand_cost"]))
        sim_cost["estimated_hourly_cost"] = "%.3f" % (float(sim_cost["estimated_total_cost"]) / float(walltime))
        sim_cost["storage_pct"] = "%.3f" % (float(sim_cost["estimated_storage_cost"]) / float(sim_cost["estimated_total_cost"]) * 100) if float(sim_cost["estimated_storage_cost"]) != 0.000 else 0
        sim_cost["compute_pct"] = "%.3f" % (float(sim_cost["compute"]["estimated_on_demand_cost"]) / float(sim_cost["estimated_total_cost"]) * 100) if float(sim_cost["compute"]["estimated_on_demand_cost"]) != 0.000 else 0
        sim_cost["compute"]["cpus"] = cpus
        return sim_cost, 200


