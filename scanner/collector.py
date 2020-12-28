import boto3
import datetime as dt
import dateutil.parser
import csv
import time
import json

class collector:
    
    def __init__(self,aws_access_key_id = None,aws_secret_access_key = None,aws_session_token = None):

        # we need to pull the access keys into the class... this is used all the time
        self.aws_access_key_id      = aws_access_key_id
        self.aws_secret_access_key  = aws_secret_access_key
        self.aws_session_token      = aws_session_token

        self.cache = {}

    def convert_timestamp(self,item_date_object):
        if isinstance(item_date_object, (dt.date,dt.datetime)):
            return item_date_object.timestamp()

    def collect_all(self):
        self.iam_generate_credential_report()
        self.sts_get_caller_identity()
        self.s3_bucketpolicy()
        self.s3_bucket_acl()
        self.ec2_describe_regions()
        self.ec2_describe_vpcs()
        self.ec2_describe_flow_logs()
        self.ec2_describe_instances()
        self.ec2_describe_securitygroups()
        self.rds_describe_db_instances()
        self.ec2_describe_subnets()
        self.ec2_describe_iam_instance_profile_associations()
        self.ec2_describe_route_tables()
        self.lambda_list_functions()
        self.cloudtrail_describe_trails()
        self.config_describe_configuration_recorders()
        self.config_describe_configuration_recorder_status()
        self.iam_policy()
        self.iam_credentials()
        self.iam_list_groups()
        self.iam_get_account_summary()
        self.iam_get_group()
        self.iam_list_attached_group_policies()
        self.iam_list_users()
        self.iam_get_account_authorization_details()
        self.iam_list_roles()
        self.iam_list_attached_role_policies()
        self.iam_list_attached_user_policies()
        self.iam_list_user_policies()
        self.dynamodb_list_tables()
        self.kms_list_keys()
        self.kms_get_key_rotation_status()
        self.iam_list_policies()
        self.iam_get_policy()

    def write_json(self,file):
        with open(file,'wt') as f:
            f.write(json.dumps(self.cache,indent = 4, default=self.convert_timestamp))
            f.close()
    
    def read_json(self,file):
        with open(file,'rt') as f:
            self.cache = json.load(f)
            f.close()

    def sts_get_caller_identity(self):

        if not 'sts' in self.cache:
            self.cache['sts'] = {}

        if not 'get_caller_identity' in self.cache['sts']:
            print ('sts - get_caller_identity')
            self.cache['sts']['get_caller_identity'] = boto3.client('sts',
                aws_access_key_id       = self.aws_access_key_id,
                aws_secret_access_key   = self.aws_secret_access_key,
                aws_session_token       = self.aws_session_token
            ).get_caller_identity()

    def dynamodb_list_tables(self):
        if not 'dynamodb' in self.cache:
            self.cache['dynamodb'] = {}
        if not 'list_tables' in self.cache['dynamodb']:
            self.cache['dynamodb']['list_tables'] = {}

            for region in self.ec2_describe_regions():
                if not region in self.cache['dynamodb']['list_tables']:
                    self.cache['dynamodb']['list_tables'][region] = []
                    print ('dynamodb - list_tables - ' + region)
                    paginator = boto3.client('dynamodb',
                        region_name				= region,
                        aws_access_key_id		= self.aws_access_key_id,
                        aws_secret_access_key	= self.aws_secret_access_key,
                        aws_session_token		= self.aws_session_token
                    ).get_paginator('list_tables')
                    for r in paginator.paginate():
                        for t in r['TableNames']:
                            print(' - ' + t)                     
                            self.cache['dynamodb']['list_tables'][region].append(t)

    def ec2_describe_securitygroups(self):
        if not 'ec2' in self.cache:
            self.cache['ec2'] = {}
        if not 'describe_security_groups' in self.cache['ec2']:
            self.cache['ec2']['describe_security_groups'] = {}
            self.ec2_describe_regions()
            for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
                print ('ec2 - describe_security_groups - ' + region)
                if not region in self.cache['ec2']['describe_security_groups']:
                    self.cache['ec2']['describe_security_groups'][region] = boto3.client('ec2',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_security_groups().get('SecurityGroups')

    def ec2_describe_instances(self):
        if not 'ec2' in self.cache:
            self.cache['ec2'] = {}
        if not 'describe_instances' in self.cache['ec2']:
            self.cache['ec2']['describe_instances'] = {}

            for region in self.ec2_describe_regions():
                if not region in self.cache['ec2']['describe_instances']:
                    self.cache['ec2']['describe_instances'][region] = []
                    print ('ec2 - describe_instances - ' + region)
                    for reservation in boto3.client('ec2',
                        region_name				= region,
                        aws_access_key_id		= self.aws_access_key_id,
                        aws_secret_access_key	= self.aws_secret_access_key,
                        aws_session_token		= self.aws_session_token
                    ).describe_instances().get('Reservations'):
                        for ec2 in reservation['Instances']:
                            print(' - ' + ec2['InstanceId'])
                            self.cache['ec2']['describe_instances'][region].append(ec2)

    def ec2_describe_subnets(self):
        if not 'ec2' in self.cache:
            self.cache['ec2'] = {}
        if not 'describe_subnets' in self.cache['ec2']:
            self.cache['ec2']['describe_subnets'] = {}

            for region in self.ec2_describe_regions():
                if not region in self.cache['ec2']['describe_subnets']:
                    self.cache['ec2']['describe_subnets'][region] = []
                    print ('ec2 - describe_subnets - ' + region)
                    paginator = boto3.client('ec2',
                        region_name				= region,
                        aws_access_key_id		= self.aws_access_key_id,
                        aws_secret_access_key	= self.aws_secret_access_key,
                        aws_session_token		= self.aws_session_token
                    ).get_paginator('describe_subnets')

                    for p in paginator.paginate():
                        for s in p['Subnets']:
                            print (' - ' + s['SubnetId'])
                            self.cache['ec2']['describe_subnets'][region].append(s)

    def ec2_describe_vpcs(self):
        if not 'ec2' in self.cache:
            self.cache['ec2'] = {}
        if not 'describe_vpcs' in self.cache['ec2']:
            self.cache['ec2']['describe_vpcs'] = {}

        for region in self.ec2_describe_regions():
            if not region in self.cache['ec2']['describe_vpcs']:
                self.cache['ec2']['describe_vpcs'][region] = []
                print('ec2 - describe_vpcs - ' + region)

                for vpc in boto3.client('ec2',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_vpcs()['Vpcs']:
                    self.cache['ec2']['describe_vpcs'][region].append(vpc)
                    print(' - ' + vpc['VpcId'])

    def ec2_describe_regions(self):
        if not 'ec2' in self.cache:
            self.cache['ec2'] = {}
        
        if not 'describe_regions' in self.cache['ec2']:
            print ('ec2 - describe_regions')
			
            self.cache['ec2']['describe_regions'] = boto3.client( 'ec2' ,
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token,
                region_name             = 'us-east-1'
            ).describe_regions()['Regions']
        return [region['RegionName'] for region in self.cache['ec2']['describe_regions']]

    def ec2_describe_flow_logs(self):
        if not 'ec2' in self.cache:
            self.cache['ec2'] = {}
        if not 'describe_flow_logs' in self.cache['ec2']:
            self.cache['ec2']['describe_flow_logs'] = {}

        for region in self.ec2_describe_regions():
            if not region in self.cache['ec2']['describe_flow_logs']:
                self.cache['ec2']['describe_flow_logs'][region] = []
                print('ec2 - describe_flow_logs - ' + region)

                for fl in boto3.client('ec2',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_flow_logs()['FlowLogs']:
                    print(' - ' + fl['FlowLogId'])
                    self.cache['ec2']['describe_flow_logs'][region].append(fl)

    def ec2_describe_iam_instance_profile_associations(self):
        if not 'ec2' in self.cache:
            self.cache['ec2'] = {}
        if not 'describe_iam_instance_profile_associations' in self.cache['ec2']:
            self.cache['ec2']['describe_iam_instance_profile_associations'] = {}
        for region in self.ec2_describe_regions():
            if not region in self.cache['ec2']['describe_iam_instance_profile_associations']:
                self.cache['ec2']['describe_iam_instance_profile_associations'][region] = []
                print('ec2 - describe_iam_instance_profile_associations - ' + region)
            
                paginator = boto3.client('ec2',
                    region_name             = region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                    ).get_paginator('describe_iam_instance_profile_associations')

                for p in paginator.paginate():
                    for i in p['IamInstanceProfileAssociations']:
                        self.cache['ec2']['describe_iam_instance_profile_associations'][region].append(i)

    def ec2_describe_route_tables(self):
        if not 'ec2' in self.cache:
            self.cache['ec2'] = {}
        if not 'describe_route_tables' in self.cache['ec2']:
            self.cache['ec2']['describe_route_tables'] = {}

        for region in self.ec2_describe_regions():
            if not region in self.cache['ec2']['describe_route_tables']:
                self.cache['ec2']['describe_route_tables'][region] = []

                paginator = boto3.client('ec2',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).get_paginator('describe_route_tables')

                print('ec2 - describe_route_tables - ' + region)
                for p in paginator.paginate():
                    self.cache['ec2']['describe_route_tables'][region].append(p['RouteTables'])

    def kms_list_keys(self):
        if not 'kms' in self.cache:
            self.cache['kms'] = {}
        if not 'list_keys' in self.cache['kms']:
            self.cache['kms']['list_keys'] = {}

        for region in self.ec2_describe_regions():
            if not region in self.cache['kms']['list_keys']:
                print('kms - list_keys - ' + region)
                self.cache['kms']['list_keys'][region] = boto3.client('kms',
                            region_name				= region,
                            aws_access_key_id		= self.aws_access_key_id,
                            aws_secret_access_key	= self.aws_secret_access_key,
                            aws_session_token		= self.aws_session_token
                ).list_keys()['Keys']
            
    def kms_get_key_rotation_status(self):
        self.kms_list_keys()

        if not 'kms' in self.cache:
            self.cache['kms'] = {}
        if not 'get_key_rotation_status' in self.cache['kms']:
            self.cache['kms']['get_key_rotation_status'] = {}

        for region in self.ec2_describe_regions():
            if not region in self.cache['kms']['get_key_rotation_status']:
                self.cache['kms']['get_key_rotation_status'][region] = {}
                for key in self.cache['kms']['list_keys'][region]:
                    
                    print('kms - get_key_rotation_status - ' + region + ' - ' + key['KeyId'])
                    
                    try:
                        self.cache['kms']['get_key_rotation_status'][region][key['KeyId']] = boto3.client('kms',
                                    region_name				= region,
                                    aws_access_key_id		= self.aws_access_key_id,
                                    aws_secret_access_key	= self.aws_secret_access_key,
                                    aws_session_token		= self.aws_session_token
                        ).get_key_rotation_status(KeyId = key['KeyId'])['KeyRotationEnabled']
                    except:
                        print('** ERROR getting get_key_rotation_status ** ')
                        self.cache['kms']['get_key_rotation_status'][region][key['KeyId']] = False

    def config_describe_configuration_recorders(self):
        if not 'config' in self.cache:
            self.cache['config'] = {}
        if not 'describe_configuration_recorders' in self.cache['config']:
            self.cache['config']['describe_configuration_recorders'] = {}

        for region in self.ec2_describe_regions():
            if not region in self.cache['config']['describe_configuration_recorders']:
                self.cache['config']['describe_configuration_recorders'][region] = []
                print('config - describe_configuration_recorders - ' + region)

                for cr in boto3.client('config',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_configuration_recorders()['ConfigurationRecorders']:
                    print(' - ' + cr['name'])
                    self.cache['config']['describe_configuration_recorders'][region].append(cr)

    def config_describe_configuration_recorder_status(self):
        if not 'config' in self.cache:
            self.cache['config'] = {}
        if not 'describe_configuration_recorder_status' in self.cache['config']:
            self.cache['config']['describe_configuration_recorder_status'] = {}

        for region in self.ec2_describe_regions():
            if not region in self.cache['config']['describe_configuration_recorder_status']:
                self.cache['config']['describe_configuration_recorder_status'][region] = []
                print('config - describe_configuration_recorder_status - ' + region)

                for cr in boto3.client('config',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_configuration_recorder_status()['ConfigurationRecordersStatus']:
                    print(' - ' + cr['name'])
                    self.cache['config']['describe_configuration_recorder_status'][region].append(cr)

    def s3_bucket_acl(self):
        if not 's3' in self.cache:
            self.cache['s3'] = {}

        if not 'bucketacl' in self.cache['s3']:
            self.cache['s3']['bucketacl'] = {}

            client = boto3.client('s3',
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
            )
        
            for bucket in client.list_buckets().get('Buckets'):
                bucketname = bucket.get('Name')
                if not bucketname in self.cache['s3']['bucketacl']:
                    self.cache['s3']['bucketacl'][bucketname] = {}

                    print ('s3 - bucketacl - ' + bucketname)
                    s3 = boto3.resource('s3',
                        aws_access_key_id		= self.aws_access_key_id,
                        aws_secret_access_key	= self.aws_secret_access_key,
                        aws_session_token		= self.aws_session_token
                    )
                    bucket_acl = s3.BucketAcl(bucketname)
                    self.cache['s3']['bucketacl'][bucketname]['grants'] = bucket_acl.grants
                    self.cache['s3']['bucketacl'][bucketname]['owner'] = bucket_acl.owner
           
    def s3_bucketpolicy(self):
        if not 's3' in self.cache:
            self.cache['s3'] = {}
        
        if not 'policy' in self.cache['s3']:
            self.cache['s3']['policy'] = {}
            
            client = boto3.client('s3',
		        aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
	        )
	
            for bucket in client.list_buckets().get('Buckets'):
                bucketname = bucket.get('Name')
                
                if not bucketname in self.cache['s3']['policy']:
                    print ('s3 - policy - ' + bucketname)
            
                    try:
                        policy = json.loads(client.get_bucket_policy(Bucket = bucketname).get('Policy'))
                    except:
                        policy = {}

                    self.cache['s3']['policy'][bucketname] = policy

    def iam_policy(self):
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        
        if not 'policy' in self.cache['iam']:
            self.cache['iam']['policy'] = {}

            print ('iam - policy')

            response = boto3.resource('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).AccountPasswordPolicy()

            self.cache['iam']['policy']['max_password_age']                 = response.max_password_age
            self.cache['iam']['policy']['minimum_password_length']          = response.minimum_password_length
            self.cache['iam']['policy']['password_reuse_prevention']        = response.password_reuse_prevention
            self.cache['iam']['policy']['allow_users_to_change_password']   = response.allow_users_to_change_password
            self.cache['iam']['policy']['require_lowercase_characters']     = response.require_lowercase_characters
            self.cache['iam']['policy']['require_numbers']                  = response.require_numbers
            self.cache['iam']['policy']['require_symbols']                  = response.require_symbols
            self.cache['iam']['policy']['require_uppercase_characters']     = response.require_uppercase_characters

    def iam_generate_credential_report(self):
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'credentials' in self.cache['iam']:
            print ('iam - generate_credential_report')
            boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).generate_credential_report()

    def iam_get_account_summary(self):
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'get_account_summary' in self.cache['iam']:
            self.cache['iam']['get_account_summary'] = []
            print ('iam - get_account_summary')
            self.cache['iam']['get_account_summary'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).get_account_summary().get('SummaryMap')

    def iam_list_groups(self):
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'list_groups' in self.cache['iam']:
            self.cache['iam']['list_groups'] = []
            print ('iam - list_groups')
            self.cache['iam']['list_groups'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).list_groups().get('Groups')

    def iam_list_roles(self):
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'list_roles' in self.cache['iam']:
            self.cache['iam']['list_roles'] = []
            print ('iam - list_roles')
            self.cache['iam']['list_roles'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).list_roles().get('Roles')

    def iam_get_group(self):
        self.iam_list_groups()

        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'get_group' in self.cache['iam']:
            self.cache['iam']['get_group'] = {}
            print('iam - get_group')
            iam = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token)
            
            for g in self.cache['iam']['list_groups']:
                GroupName = g['GroupName']
                if not GroupName in self.cache['iam']['get_group']:
                    self.cache['iam']['get_group'][GroupName] = {}
                    print(' - ' + GroupName)
                    self.cache['iam']['get_group'][GroupName] = iam.get_group(GroupName = GroupName)
    
    def iam_list_attached_role_policies(self):
        self.iam_list_roles()

        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'list_attached_role_policies' in self.cache['iam']:
            self.cache['iam']['list_attached_role_policies'] = {}
            print('iam - list_attached_role_policies')
            iam = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token)
            
            for g in self.cache['iam']['list_roles']:
                RoleName = g['RoleName']
                if not RoleName in self.cache['iam']['list_attached_role_policies']:
                    self.cache['iam']['list_attached_role_policies'][RoleName] = []
                    print(' - ' + RoleName)
                    self.cache['iam']['list_attached_role_policies'][RoleName] = iam.list_attached_role_policies(RoleName = RoleName)['AttachedPolicies']

    def iam_list_attached_user_policies(self):
        self.iam_list_users()
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'list_attached_user_policies' in self.cache['iam']:
            self.cache['iam']['list_attached_user_policies'] = {}
            print('iam - list_attached_user_policies')
            iam = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token)
            
            for g in self.cache['iam']['list_users']:
                UserName = g['UserName']
                if not UserName in self.cache['iam']['list_attached_user_policies']:
                    self.cache['iam']['list_attached_user_policies'][UserName] = []
                    print(' - ' + UserName)
                    self.cache['iam']['list_attached_user_policies'][UserName] = iam.list_attached_user_policies(UserName = UserName)['AttachedPolicies']

    def iam_list_user_policies(self):
        self.iam_list_users()
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'list_user_policies' in self.cache['iam']:
            self.cache['iam']['list_user_policies'] = {}
            print('iam - list_user_policies')
            iam = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token)
            
            for g in self.cache['iam']['list_users']:
                UserName = g['UserName']
                if not UserName in self.cache['iam']['list_user_policies']:
                    self.cache['iam']['list_user_policies'][UserName] = []
                    print(' - ' + UserName)
                    self.cache['iam']['list_user_policies'][UserName] = iam.list_user_policies(UserName = UserName)['PolicyNames']

    def iam_list_attached_group_policies(self):
        self.iam_list_groups()

        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'list_attached_group_policies' in self.cache['iam']:
            self.cache['iam']['list_attached_group_policies'] = {}
            print('iam - list_attached_group_policies')
            iam = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token)
            
            for g in self.cache['iam']['list_groups']:
                GroupName = g['GroupName']
                if not GroupName in self.cache['iam']['list_attached_group_policies']:
                    self.cache['iam']['list_attached_group_policies'][GroupName] = []
                    print(' - ' + GroupName)
                    self.cache['iam']['list_attached_group_policies'][GroupName] = iam.list_attached_group_policies(GroupName = GroupName)['AttachedPolicies']
    
    def iam_list_users(self):
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'list_users' in self.cache['iam']:
            self.cache['iam']['list_users'] = []

            print('iam - list_users')
            self.cache['iam']['list_users'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token).list_users()['Users']

    def iam_get_account_authorization_details(self):
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        if not 'get_account_authorization_details' in self.cache['iam']:
            self.cache['iam']['get_account_authorization_details'] = []

            print('iam - get_account_authorization_details')
            self.cache['iam']['get_account_authorization_details'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token).get_account_authorization_details() #['Users']         

    def age(self,dte):
        if dte == 'not_supported' or dte == 'N/A' or dte == 'no_information':
            return -1
        else:
            result = dt.date.today() - dateutil.parser.parse(dte).date()
            return result.days

    def iam_credentials(self):
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        
        if not 'credentials' in self.cache['iam']:
            self.cache['iam']['credentials'] = []

            print ('iam - credentials')

            # == extract the iam user details, one by one
            iam = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            )

            response = iam.generate_credential_report()
            while response['State'] != 'COMPLETE':
                time.sleep(2)
                response = iam.generate_credential_report()

            response = iam.get_credential_report()
            credential_report_csv = response['Content'].decode('utf-8')
            reader = csv.DictReader(credential_report_csv.splitlines())
            
            for row in reader:
                row['_password_last_changed_age']		= self.age(row['password_last_changed'])
                row['_password_last_used_age']			= self.age(row['password_last_used'])
                row['_access_key_1_last_rotated_age']	= self.age(row['access_key_1_last_rotated'])
                row['_access_key_1_last_used_date_age']	= self.age(row['access_key_1_last_used_date'])
                row['_access_key_2_last_rotated_age']	= self.age(row['access_key_2_last_rotated'])
                row['_access_key_2_last_used_date_age']	= self.age(row['access_key_2_last_used_date'])
                row['_user_creation_time_age']			= self.age(row['user_creation_time'])
                print(' - ' + row['user'])
                self.cache['iam']['credentials'].append(row)

    def rds_describe_db_instances(self):
        if not 'rds' in self.cache:
            self.cache['rds'] = {}
        if not 'describe_db_instances' in self.cache['rds']:
            self.cache['rds']['describe_db_instances'] = {}

            for region in self.ec2_describe_regions():
                if not region in self.cache['rds']['describe_db_instances']:
                    self.cache['rds']['describe_db_instances'][region] = []
                    print ('rds - describe_db_instances - ' + region)
                    for db in boto3.client('rds',
                        region_name				= region,
                        aws_access_key_id		= self.aws_access_key_id,
                        aws_secret_access_key	= self.aws_secret_access_key,
                        aws_session_token		= self.aws_session_token
                    ).describe_db_instances().get('DBInstances'):
                        print(' - ' + db['DbiResourceId'])
                        self.cache['rds']['describe_db_instances'][region].append(db)

    def cloudtrail_describe_trails(self):
        if not 'cloudtrail' in self.cache:
            self.cache['cloudtrail'] = {}

        if not 'describe_trails' in self.cache['cloudtrail']:
            self.cache['cloudtrail']['describe_trails'] = {}

        for region in self.ec2_describe_regions():
            if not region in self.cache['cloudtrail']['describe_trails']:
                self.cache['cloudtrail']['describe_trails'][region] = []
                print ('cloudtrail - ' + region)
                ct = boto3.client('cloudtrail',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                )
                
                for trail in ct.describe_trails()["trailList"]:
                    print(' - ' + trail['TrailARN'])
                    trail['get_trail_status'] = ct.get_trail_status(Name=trail['TrailARN'])
                    trail['get_event_selectors'] = ct.get_event_selectors(TrailName=trail['TrailARN'])
                    self.cache['cloudtrail']['describe_trails'][region].append(trail)

    def lambda_list_functions(self):
        if not 'lambda' in self.cache:
            self.cache['lambda'] = {}

        if not 'list_functions' in self.cache['lambda']:
            self.cache['lambda']['list_functions'] = {}

            for region in self.ec2_describe_regions():
                if not region in self.cache['lambda']['list_functions']:
                    self.cache['lambda']['list_functions'][region] = []
                    print ('lambda - list_functions - ' + region)

                    paginator = boto3.client('lambda',
                        region_name				= region,
                        aws_access_key_id		= self.aws_access_key_id,
                        aws_secret_access_key	= self.aws_secret_access_key,
                        aws_session_token		= self.aws_session_token
                    ).get_paginator('list_functions')

                    for lf in paginator.paginate():
                        for l in lf['Functions']:
                            print(' - ' + l['FunctionName'])
                            self.cache['lambda']['list_functions'][region].append(l)
                        
    def iam_list_policies(self):
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        
        if not 'list_policies' in self.cache['iam']:
            self.cache['iam']['list_policies'] = []

            print ('iam - list_policies')
            self.cache['iam']['list_policies'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).list_policies()['Policies']

    def iam_get_policy(self):
        if not 'iam' in self.cache:
            self.cache['iam'] = {}
        
        if not 'get_policy_version' in self.cache['iam']:
            self.cache['iam']['get_policy_version'] = {}

            iam = boto3.client('iam',
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                )
            
            for p in self.cache['iam']['list_policies']:
                
                if not p['PolicyName'] in self.cache['iam']['get_policy_version']:
                    print('iam - get_policy_version - ' + p['PolicyName'])

                    # todo - confirm if this thing wants the policy name, or the policy arn
                    self.cache['iam']['get_policy_version'][p['PolicyName']] = iam.get_policy_version(PolicyArn = p['Arn'], VersionId = p['DefaultVersionId'])['PolicyVersion']
                

        