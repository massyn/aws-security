import boto3

class sts:
    def __init__(self):
        self.data = {}

    def assume_role(self,a,b,c,account,role = 'AWSSecurityInfoReadOnlyRole',ExternalId = '717CF4D0BF1E46C3CD59B0B8BF85D11314896814C522CE67D59CBE6F58DA1866'):

        RoleArn = 'arn:aws:iam::{account}:role/{role}'.format(account = account, role = role)

        #try:
        if 1 ==1:
            assume_role = boto3.client('sts',
                aws_access_key_id = a,
                aws_secret_access_key = b,
                aws_session_token = c
            ).assume_role(
                RoleArn=RoleArn,
                RoleSessionName='string',
                ExternalId=ExternalId
            )
            aws_access_key_id       = assume_role['Credentials']['AccessKeyId'];
            aws_secret_access_key   = assume_role['Credentials']['SecretAccessKey'];
            aws_session_token       = assume_role['Credentials']['SessionToken'];
            print ('** assume-role succeeded **')
            return (aws_access_key_id,aws_secret_access_key,aws_session_token)
        #except:
        else:
            print ("ERROR - could not create a token to account")
            return (None,None,None)