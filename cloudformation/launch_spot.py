# This is the code embedded in the automated Lambda function

import boto3
import base64
import os
import json

def lambda_handler(event, context):
    
    IamInstanceProfile  = os.environ['IamInstanceProfile']
    ImageId             = os.environ['ImageId']
    SecurityGroup       = os.environ['SecurityGroup']
    SubnetId            = os.environ['SubnetId']
    S3Bucket            = os.environ['S3Bucket']

    UserData = '#!/bin/bash\n'
    UserData += 'export BUCKET=' + S3Bucket + '\n'

    UserData += '''
export dte=`date '+%Y/%m/%d'`

yum update -y
yum install python3 -y
yum install git -y
yum install awscli -y
pip3 install boto3
cd /tmp
mkdir /tmp/secreport
git clone http://github.com/massyn/aws-security

python3 aws-security/scanner/scanner.py --json /tmp/secreport/%a.json --html /tmp/secreport/%a.html > /tmp/secreport/output.log 2>&1
aws s3 cp /tmp/secreport/* s3://$BUCKET/$dte/

# -- do a shutdown now
#shutdown now
'''

    instance = boto3.client(
        'ec2',
        region_name = 'us-east-1'
    ).request_spot_instances(
        InstanceCount=1,
        LaunchSpecification={
            'BlockDeviceMappings': [
                {
                    'DeviceName' : '/dev/xvda',
                    'Ebs': {
                        'DeleteOnTermination': True,
                        'VolumeSize': 8,
                        'VolumeType': 'gp2'
                    }
                }
            ],
            'IamInstanceProfile': { 'Name': IamInstanceProfile },
            'ImageId': ImageId,
            'InstanceType': 't2.micro',
            'NetworkInterfaces': [
                {
                    'DeviceIndex' : 0,
                    'AssociatePublicIpAddress': True,
                    'DeleteOnTermination': True,
                    'Groups': [ SecurityGroup ],
                    'SubnetId' : SubnetId
                },
            ],
            'Placement': { 'Tenancy': 'default' },
            'UserData': base64.b64encode(UserData.encode('ascii')).decode('ascii')
        },
        Type='one-time',
        InstanceInterruptionBehavior='terminate'
    )

    return { 'statusCode': 200, 'body': json.dumps(instance) }


