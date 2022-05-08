import boto3

def disable_security_hub():

    for region in [region['RegionName'] for region in boto3.client('ec2',region_name = 'us-east-1').describe_regions()['Regions']]:
        client = boto3.client('securityhub',region_name=region)
        # -- disable security hub
        print(f'Disabling Security Hub in {region}')
        try:
            x = client.disable_security_hub()
            print(' ** SUCCESS **')
        except:
            print(' - it might already be disabled')

def enable_security_hub():

    for region in [region['RegionName'] for region in boto3.client('ec2',region_name = 'us-east-1').describe_regions()['Regions']]:
        client = boto3.client('securityhub',region_name=region)
        # -- enable security hub
        print(f'Enabling Security Hub in {region}')
        try:
            x = client.enable_security_hub()
            print(' ** SUCCESS **')
        except:
            print(' - it might already be enabled')

        # -- enable prowler import
        print(f'Enabling prowler ARN in {region}')
        try:
            response = client.enable_import_findings_for_product(
                ProductArn=f'arn:aws:securityhub:{region}::product/prowler/prowler'
            )
            print(' ** SUCCESS **')
        except:
            print(' - it might already be enabled')

        # -- disable the active standards.  For this use case, we won't use it.
        standards = []
        print(f'finding all enabled standards in {region}...')
        for x in client.get_enabled_standards()['StandardsSubscriptions']:
            standards.append(x['StandardsSubscriptionArn'])
            print(f" - {x['StandardsSubscriptionArn']}")

        if len(standards) > 0:
            print(f'now disable it...')            
            client.batch_disable_standards(StandardsSubscriptionArns= standards )
        else:
            print(' ** nothing to disable **')
        
enable_security_hub()
#disable_security_hub()