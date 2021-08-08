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
    
    print('IamInstanceProfile   = ' + IamInstanceProfile)
    print('ImageId              = ' + ImageId)
    print('SecurityGroup        = ' + SecurityGroup)
    print('SubnetId             = ' + SubnetId)
    print('S3Bucket             = ' + S3Bucket)
    print('SlackWebhook         = ' + SlackWebhook)

    UserData = '''#!/bin/bash
export instanceId=`curl -q http://169.254.169.254/latest/dynamic/instance-identity/document |grep instanceId | awk {'print \$3'} | cut -b 2-20`
[[ ! -z "{SlackWebhook}" ]] && /usr/bin/curl -X POST -H 'Content-type: application/json' --data '{"text":":racing_motorcycle: AWS Security Info instance $instanceId has been created."}' {SlackWebhook}

export dte=`date '+%Y/%m/%d'`

yum update -y
yum install python3 -y
yum install git -y
yum install awscli -y
pip3 install boto3

cd /tmp
mkdir /tmp/secreport
git clone http://github.com/massyn/aws-security

python3 aws-security/scanner/scanner.py --json /tmp/secreport/%a.json --html /tmp/secreport/%a.html --slack {SlackWebhook} > /tmp/secreport/output.log 2>&1
aws s3 cp /tmp/secreport/ s3://{S3Bucket}/$dte/ --recursive

# -- do a shutdown now
#shutdown now
'''.format(S3Bucket = S3Bucket, SlackWebhook = SlackWebhook)

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


