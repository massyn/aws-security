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
    SlackWebhook        = os.environ['SlackWebhook']
    additional          = os.environ['additional']
    
    print('IamInstanceProfile   = ' + IamInstanceProfile)
    print('ImageId              = ' + ImageId)
    print('SecurityGroup        = ' + SecurityGroup)
    print('SubnetId             = ' + SubnetId)
    print('S3Bucket             = ' + S3Bucket)
    print('SlackWebhook         = ' + SlackWebhook)
    print('additional           = ' + additional)
    print('')

    UserData = '''#!/bin/bash
export dte=`date '+%Y/%m/%d'`

yum update -y
yum install python3 git awscli -y
pip3 install boto3

cd /tmp
mkdir /tmp/secreport
git clone http://github.com/massyn/aws-security

python3 aws-security/scanner/scanner.py --json /tmp/secreport/%a.json --html s3://{S3Bucket}/$dte/%a.html --slack {SlackWebhook} {additional}> /tmp/secreport/output.log 2>&1
aws s3 cp /tmp/secreport/ s3://{S3Bucket}/$dte/ --recursive

# -- do a shutdown now
shutdown now
'''.format(S3Bucket = S3Bucket, SlackWebhook = SlackWebhook, additional = additional)

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
            'UserData': base64.b64encode(UserData.encode('ascii')).decode('ascii'),
        },
        Type='one-time',
        InstanceInterruptionBehavior='terminate'
    )
    print(instance)

    return { 'statusCode': 200, 'body': 'ok' }


