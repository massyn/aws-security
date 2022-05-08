import boto3
import requests
import json
import argparse

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

def main():
    parser = argparse.ArgumentParser(description='AWS Bastion Script')
    parser.add_argument('--GroupId',help='Enter the security group Id', required = True)
    parser.add_argument('--region',help='Enter the AWS region name', required = True)
    parser.add_argument('--ports', metavar='N', type=int, nargs='+', help='Provide all ports to be opened')

    args = parser.parse_args()

    Port = args.ports

    closePort(region_name = args.region,  GroupId = args.GroupId)
    for p in Port:
        openPort(region_name = args.region,  GroupId = args.GroupId, Port = p)

main()