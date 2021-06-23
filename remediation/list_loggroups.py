import boto3

def find_regions(ACCESS_KEY = None,SECRET_KEY = None,SESSION_TOKEN = None):
    return [region['RegionName'] for region in boto3.client('ec2',
            region_name = 'us-east-1',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN).describe_regions()['Regions']]


def list_loggroups(ACCESS_KEY = None,SECRET_KEY = None,SESSION_TOKEN = None):
    total = 0
    print('#region;loggroup;storedBytes;retentionInDays')
    for region in find_regions(ACCESS_KEY,SECRET_KEY,SESSION_TOKEN):
        client = boto3.client('logs',
            region_name = region,
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN)

        for p in client.get_paginator('describe_log_groups').paginate():
            for l in p['logGroups']:
                print('{region};{logGroupName};{storedBytes};{retentionInDays}'.format(region = region, logGroupName = l['logGroupName'],retentionInDays = l.get('retentionInDays','No retention set'), storedBytes = l['storedBytes']))
                total += l['storedBytes']
                
                # -- if you want to set a global retention policy, uncomment this line
                if not 'retentionInDays' in l:
                    response = client.put_retention_policy(
                        logGroupName=l['logGroupName'],
                        retentionInDays=90
                    )
                    print(response)


    print('# Total bytes = ' + str(total))

                
                

         

if __name__ == "__main__":
    list_loggroups()