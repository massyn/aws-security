import boto3

class sts:
    def __init__(self):
        self.data = {}

    def assume_role(self,a,b,c,account,role,ExternalId):

        RoleArn = 'arn:aws:iam::{account}:role/{role}'.format(account = account, role = role)
        
        if ExternalId != None:
            assume_role = boto3.client('sts',
                aws_access_key_id = a,
                aws_secret_access_key = b,
                aws_session_token = c
            ).assume_role(
                RoleArn=RoleArn,
                RoleSessionName='string',
                ExternalId=ExternalId
            )
        else:
            assume_role = boto3.client('sts',
                aws_access_key_id = a,
                aws_secret_access_key = b,
                aws_session_token = c
            ).assume_role(
                RoleArn=RoleArn,
                RoleSessionName='string'
            )

        aws_access_key_id       = assume_role['Credentials']['AccessKeyId'];
        aws_secret_access_key   = assume_role['Credentials']['SecretAccessKey'];
        aws_session_token       = assume_role['Credentials']['SessionToken'];
        print ('** assume-role succeeded **')
        return (aws_access_key_id,aws_secret_access_key,aws_session_token)
        