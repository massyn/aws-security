import boto3
import requests
import json

def openPort(**Z):
    # == get my IP address
    myIp = json.loads(requests.get('https://api.ipify.org?format=json').content)['ip']
    print(myIp)

    output = boto3.client('ec2',region_name = Z['region_name']).authorize_security_group_ingress(
        GroupId = Z['GroupId'],
        IpPermissions=[
            {
                'IpProtocol'    : 'tcp', 
                'FromPort'      : Z['Port'],
                'ToPort'        : Z['Port'],
                'IpRanges': [{
                    'CidrIp': f'{myIp}/32',
                    'Description': 'My own IP'
                }]
            }
        ]
    )

    return output['Return']

def closePort(**Z):
    ec2 = boto3.client('ec2',region_name = Z['region_name'])
    for x in ec2.describe_security_groups(GroupIds=[Z['GroupId']])['SecurityGroups']:
        output = ec2.revoke_security_group_ingress(GroupId = Z['GroupId'], IpPermissions = x['IpPermissions'])
        print(output['Return'])

# ===================== my parameters
GroupId = 'sg-0da7f476c0e40339c'        # -- modify this parameter to your security group name
region_name = 'ap-southeast-2'          # -- modify this parameter to the region where you operate
Port = 22                               # -- Port 22 for Linux, 3389 for Windows.

closePort(region_name = region_name,  GroupId = GroupId)
openPort(region_name = region_name,  GroupId = GroupId, Port = Port)
