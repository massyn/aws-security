import boto3
import json


def read_cloudtrail_events(a = None,b = None,c = None):
    for e in boto3.client('cloudtrail',
        aws_access_key_id=a,
        aws_secret_access_key=b,
        aws_session_token=c).get_paginator('lookup_events').paginate():
        
        for event in e.get('Events'):
            CloudTrailEvent = json.loads(event['CloudTrailEvent'])

            print(CloudTrailEvent['eventTime'])

read_cloudtrail_events()