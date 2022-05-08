# import a VirtualBox vhd as an ec2 AMI

# https://gist.github.com/peterforgacs/abebc777fcd6f4b67c07b2283cd31777

import boto3
import json

def create_vmimport_role():
    client = boto3.client('iam')
    response = client.create_role(
        RoleName='vmimport',
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": { "Service": "vmie.amazonaws.com" },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals":{
                        "sts:Externalid": "vmimport"
                        }
                    }
                }
            ]
        })
    )

def attach_policy_to_role(S3Bucket):
    client = boto3.client('iam')
    response = client.put_role_policy(
        RoleName='vmimport',
        PolicyName='vmimport',
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:ListBucket",
                            "s3:GetBucketLocation"
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{S3Bucket}"
                        ]
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject"
                        ],
                        "Resource": [
                            f"arn:aws:s3:::{S3Bucket}/*"
                        ]
                    },
                    {
                        "Effect": "Allow",
                        "Action":[
                            "ec2:ModifySnapshotAttribute",
                            "ec2:CopySnapshot",
                            "ec2:RegisterImage",
                            "ec2:Describe*"
                        ],
                        "Resource": "*"
                    }
                ]
            }
        )
    )



def import_image(**KW):
    client = boto3.client('ec2', region_name = KW['region_name'])

    response = client.import_image(
        Description=KW['Description'],
        DiskContainers=[
            {
                'Description': KW['Description'],
                'Format': 'vhd',
                'UserBucket': {
                    'S3Bucket': KW['S3Bucket'],
                    'S3Key': KW['S3Key']
                }
            },
        ]
    )
    print(response)

#create_vmimport_role()
#attach_policy_to_role('buckename')


#exit(0)
import_image(
    region_name = 'ap-southeast-2',
    S3Bucket = 'bucketname',
    S3Key = 'something.vhd',
    Description = 'Image name'
)