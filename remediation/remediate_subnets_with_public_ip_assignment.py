import boto3

def find_regions(ACCESS_KEY = None,SECRET_KEY = None,SESSION_TOKEN = None):
    return [region['RegionName'] for region in boto3.client('ec2', region_name = 'us-east-1',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN).describe_regions()['Regions']]
			
		
def find_subnets(region,ACCESS_KEY = None,SECRET_KEY = None,SESSION_TOKEN = None):
	
	paginator = boto3.client('ec2',
		region_name				= region,
		aws_access_key_id		= ACCESS_KEY,
		aws_secret_access_key	= SECRET_KEY,
		aws_session_token		= SESSION_TOKEN
	).get_paginator('describe_subnets')

	result = []
	for p in paginator.paginate():
		for s in p['Subnets']:
			print(' --> ' + s['SubnetId'] + ' = ' + str(s['MapPublicIpOnLaunch']))
			if s['MapPublicIpOnLaunch']:
				response = boto3.client('ec2',
					region_name				= region,
					aws_access_key_id		= ACCESS_KEY,
					aws_secret_access_key	= SECRET_KEY,
					aws_session_token		= SESSION_TOKEN
				).modify_subnet_attribute(
					MapPublicIpOnLaunch	= {'Value': False },
					SubnetId			= s['SubnetId']
				)
				
		
		
def remediate_subnets_with_public_ip_assignment(ACCESS_KEY = None,SECRET_KEY = None,SESSION_TOKEN = None):
	"""
		Find all subnets, and disable the assignment of public IP addresses
	"""
	
	for region in find_regions(ACCESS_KEY,SECRET_KEY,SESSION_TOKEN):
		print(region)
		find_subnets(region,ACCESS_KEY,SECRET_KEY,SESSION_TOKEN)

if __name__ == "__main__":		
	remediate_subnets_with_public_ip_assignment()
	
	
