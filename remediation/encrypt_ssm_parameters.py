import boto3

def find_regions(ACCESS_KEY = None,SECRET_KEY = None,SESSION_TOKEN = None):
    return [region['RegionName'] for region in boto3.client('ec2', region_name = 'us-east-1',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN).describe_regions()['Regions']]

def encrypt_ssm_parameters(ACCESS_KEY = None,SECRET_KEY = None,SESSION_TOKEN = None):
    for region in find_regions(ACCESS_KEY,SECRET_KEY,SESSION_TOKEN):
        print(region)
        ssm = boto3.client('ssm',
            region_name				= region,
            aws_access_key_id		= ACCESS_KEY,
            aws_secret_access_key	= SECRET_KEY,
            aws_session_token		= SESSION_TOKEN
        )

        paginator = ssm.get_paginator('get_parameters_by_path')
        for r in paginator.paginate(
            Path='/',
            Recursive=True
        ):
            for t in r['Parameters']:
                
                if t['Type'] == 'SecureString':
                    print(' - ' + t['Name'] + ' --> ENCRYPTED')
                else:
                    print(' - ' + t['Name'] + ' --> !! NOT ENCRYPTED !!')
                    try:
                        response = ssm.put_parameter(
                            Name=t['Name'] ,
                            Value=t['Value'],
                            Type='SecureString',
                            Overwrite=True,
                            DataType=t['DataType']
                        )
                        print(response)
                    except:
                        print(' ** UNABLE TO CHANGE THE PARAMETER **')
                    


if __name__ == "__main__":		
	encrypt_ssm_parameters()