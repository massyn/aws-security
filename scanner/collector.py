import boto3
import datetime as dt
import dateutil.parser
import csv
import time
import json
import os.path

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
        self.ec2_describe_regions()             # this one must be at the top.. it is needed for all the others
        self.sts_get_caller_identity()
        self.s3_bucketpolicy()
        self.s3_bucket_acl()
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
        self.cloudwatch_describe_alarms()
        self.logs_describe_metric_filters()
        self.sns_list_topics()
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
        self.guardduty_list_detectors()
        self.dynamodb_list_tables()
        self.kms_list_keys()
        self.kms_get_key_rotation_status()
        self.iam_list_policies()
        self.iam_get_policy()
        

    def write_json(self):
        with open(self.data_file,'wt') as f:
            f.write(json.dumps(self.cache,indent = 4, default=self.convert_timestamp))
            f.close()
    
    def read_json(self,file):
        self.data_file = file
        if os.path.isfile(file):
            with open(file,'rt') as f:
                self.cache = json.load(f)
                f.close()

    def check_cache(self,p1,p2,p3 = None, dft = []):

        timeout = 3600

        # -- create the timestamp if it doesn't exist
        if not 'timestamp' in self.cache:
            self.cache['timestamp'] = {}
        
        if not p1 in self.cache['timestamp']:
            self.cache['timestamp'][p1] = {}

        if not p2 in self.cache['timestamp'][p1]:
            if p3 == None:
                self.cache['timestamp'][p1][p2] = 0
            else:
                self.cache['timestamp'][p1][p2] = {}

        if p3 != None and p3 not in self.cache['timestamp'][p1][p2]:
            self.cache['timestamp'][p1][p2][p3] = 0

        # -- create the cache if it doesn't exist
        if not p1 in self.cache:
            self.cache[p1] = {}

        if not p2 in self.cache[p1]:
            if p3 == None:
                self.cache[p1][p2] = dft
                self.cache['timestamp'][p1][p2] = 0
            else:
                self.cache[p1][p2] = {}
                self.cache[p1][p2][p3] = dft
                self.cache['timestamp'][p1][p2][p3] = 0

        if p3 != None and p3 not in self.cache[p1][p2]:
            self.cache[p1][p2][p3] = dft
    
        epoch_time = int(time.time())

        if p3 == None:
            timestamp = self.cache['timestamp'][p1][p2]
        else:
            timestamp = self.cache['timestamp'][p1][p2][p3]

        if (epoch_time - timestamp) > timeout:
            if p3 == None:
                print (p1 + ' - ' + p2)
                self.cache['timestamp'][p1][p2] = epoch_time

            else:
                print (p1 + ' - ' + p2 + ' - ' + p3)
                self.cache['timestamp'][p1][p2][p3] = epoch_time
            
            return True
        else:
            return False
    
    def age(self,dte):
        if dte == 'not_supported' or dte == 'N/A' or dte == 'no_information':
            return -1
        else:
            result = dt.date.today() - dateutil.parser.parse(dte).date()
            return result.days


    # =======================================
    def sts_get_caller_identity(self):
        if self.check_cache('sts','get_caller_identity',None,{}):
            self.cache['sts']['get_caller_identity'] = boto3.client('sts',
                aws_access_key_id       = self.aws_access_key_id,
                aws_secret_access_key   = self.aws_secret_access_key,
                aws_session_token       = self.aws_session_token
            ).get_caller_identity()
            self.write_json()

    def dynamodb_list_tables(self):
            for region in self.ec2_describe_regions():
                if self.check_cache('dynamodb','list_tables',region,[]):
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
                            self.write_json()

    def ec2_describe_securitygroups(self):
        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            if self.check_cache('ec2','describe_security_groups',region,{}):
                self.cache['ec2']['describe_security_groups'][region] = boto3.client('ec2',
                region_name				= region,
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).describe_security_groups().get('SecurityGroups')
            self.write_json()

    def ec2_describe_instances(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('ec2','describe_instances',region,[]):
                for reservation in boto3.client('ec2',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_instances().get('Reservations'):
                    for ec2 in reservation['Instances']:
                        print(' - ' + ec2['InstanceId'])
                        self.cache['ec2']['describe_instances'][region].append(ec2)
                self.write_json()

    def ec2_describe_subnets(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('ec2','describe_subnets',region,[]):
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
                self.write_json()

    def ec2_describe_vpcs(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('ec2','describe_vpcs',region,[]):
                for vpc in boto3.client('ec2',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_vpcs()['Vpcs']:
                    self.cache['ec2']['describe_vpcs'][region].append(vpc)
                    print(' - ' + vpc['VpcId'])
            self.write_json()

    def ec2_describe_regions(self):
        if self.check_cache('ec2','describe_regions',None,{}):
            self.cache['ec2']['describe_regions'] = boto3.client( 'ec2' ,
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token,
                region_name             = 'us-east-1'
            ).describe_regions()['Regions']
            self.write_json()
        return [region['RegionName'] for region in self.cache['ec2']['describe_regions']]

    def ec2_describe_flow_logs(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('ec2','describe_flow_logs',region,[]):
                for fl in boto3.client('ec2',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_flow_logs()['FlowLogs']:
                    print(' - ' + fl['FlowLogId'])
                    self.cache['ec2']['describe_flow_logs'][region].append(fl)
                self.write_json()

    def ec2_describe_iam_instance_profile_associations(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('ec2','describe_iam_instance_profile_associations',region,[]):
                paginator = boto3.client('ec2',
                    region_name             = region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                    ).get_paginator('describe_iam_instance_profile_associations')

                for p in paginator.paginate():
                    for i in p['IamInstanceProfileAssociations']:
                        self.cache['ec2']['describe_iam_instance_profile_associations'][region].append(i)
                self.write_json()

    def ec2_describe_route_tables(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('ec2','describe_route_tables',region,[]):
                paginator = boto3.client('ec2',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).get_paginator('describe_route_tables')

                for p in paginator.paginate():
                    self.cache['ec2']['describe_route_tables'][region].append(p['RouteTables'])
                self.write_json()

    def kms_list_keys(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('kms','list_keys',region,{}):
                self.cache['kms']['list_keys'][region] = boto3.client('kms',
                            region_name				= region,
                            aws_access_key_id		= self.aws_access_key_id,
                            aws_secret_access_key	= self.aws_secret_access_key,
                            aws_session_token		= self.aws_session_token
                ).list_keys()['Keys']
                self.write_json()
            
    def kms_get_key_rotation_status(self):
        self.kms_list_keys()

        if not 'kms' in self.cache:
            self.cache['kms'] = {}
        if not 'get_key_rotation_status' in self.cache['kms']:
            self.cache['kms']['get_key_rotation_status'] = {}

        for region in self.ec2_describe_regions():
            if self.check_cache('kms','get_key_rotation_status',region,{}):
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
                self.write_json()

    def config_describe_configuration_recorders(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('config','describe_configuration_recorders',region,[]):
                for cr in boto3.client('config',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_configuration_recorders()['ConfigurationRecorders']:
                    print(' - ' + cr['name'])
                    self.cache['config']['describe_configuration_recorders'][region].append(cr)
                self.write_json()

    def config_describe_configuration_recorder_status(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('config','describe_configuration_recorder_status',region,[]):
                for cr in boto3.client('config',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_configuration_recorder_status()['ConfigurationRecordersStatus']:
                    print(' - ' + cr['name'])
                    self.cache['config']['describe_configuration_recorder_status'][region].append(cr)
                self.write_json()

    def s3_bucket_acl(self):
        
            client = boto3.client('s3',
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
            )
        
            for bucket in client.list_buckets().get('Buckets'):
                bucketname = bucket.get('Name')

                if self.check_cache('s3','bucketacl',bucketname,{}):
                    s3 = boto3.resource('s3',
                        aws_access_key_id		= self.aws_access_key_id,
                        aws_secret_access_key	= self.aws_secret_access_key,
                        aws_session_token		= self.aws_session_token
                    )
                    bucket_acl = s3.BucketAcl(bucketname)
                    self.cache['s3']['bucketacl'][bucketname]['grants'] = bucket_acl.grants
                    self.cache['s3']['bucketacl'][bucketname]['owner'] = bucket_acl.owner
                    self.write_json()
           
    def s3_bucketpolicy(self):
        client = boto3.client('s3',
		        aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
        )
	
        for bucket in client.list_buckets().get('Buckets'):
            bucketname = bucket.get('Name')

            if self.check_cache('s3','policy',bucketname,{}):
                try:
                    policy = json.loads(client.get_bucket_policy(Bucket = bucketname).get('Policy'))
                except:
                    policy = {}

                self.cache['s3']['policy'][bucketname] = policy
                self.write_json()

    def iam_policy(self):
        if self.check_cache('iam','policy',None,{}):
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
            self.write_json()

    def iam_generate_credential_report(self):
        if self.check_cache('iam','generate_credential_report',None,{}):
            boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).generate_credential_report()

    def iam_get_account_summary(self):
        if self.check_cache('iam','get_account_summary',None,[]):
            self.cache['iam']['get_account_summary'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).get_account_summary().get('SummaryMap')
            self.write_json()

    def iam_list_groups(self):
        if self.check_cache('iam','list_groups',None,[]):
            self.cache['iam']['list_groups'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).list_groups().get('Groups')
            self.write_json()

    def iam_list_roles(self):
        if self.check_cache('iam','list_roles',None,[]):
            self.cache['iam']['list_roles'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).list_roles().get('Roles')
            self.write_json()

    def iam_get_group(self):
        self.iam_list_groups()
        
        iam = boto3.client('iam',
            aws_access_key_id		= self.aws_access_key_id,
            aws_secret_access_key	= self.aws_secret_access_key,
            aws_session_token		= self.aws_session_token)
        
        for g in self.cache['iam']['list_groups']:
            GroupName = g['GroupName']
            if self.check_cache('iam','get_group',GroupName,{}):
                self.cache['iam']['get_group'][GroupName] = iam.get_group(GroupName = GroupName)
                self.write_json()
    
    def iam_list_attached_role_policies(self):
        self.iam_list_roles()
        iam = boto3.client('iam',
            aws_access_key_id		= self.aws_access_key_id,
            aws_secret_access_key	= self.aws_secret_access_key,
            aws_session_token		= self.aws_session_token)
        
        for g in self.cache['iam']['list_roles']:
            RoleName = g['RoleName']
            if self.check_cache('iam','list_attached_role_policies',RoleName,[]):
                self.cache['iam']['list_attached_role_policies'][RoleName] = iam.list_attached_role_policies(RoleName = RoleName)['AttachedPolicies']
                self.write_json()

    def iam_list_attached_user_policies(self):
        self.iam_list_users()
        
        iam = boto3.client('iam',
            aws_access_key_id		= self.aws_access_key_id,
            aws_secret_access_key	= self.aws_secret_access_key,
            aws_session_token		= self.aws_session_token)
        
        for g in self.cache['iam']['list_users']:
            UserName = g['UserName']
            if self.check_cache('iam','list_attached_user_policies',UserName,[]):
                self.cache['iam']['list_attached_user_policies'][UserName] = iam.list_attached_user_policies(UserName = UserName)['AttachedPolicies']
                self.write_json()

    def iam_list_user_policies(self):
        self.iam_list_users()
        iam = boto3.client('iam',
            aws_access_key_id		= self.aws_access_key_id,
            aws_secret_access_key	= self.aws_secret_access_key,
            aws_session_token		= self.aws_session_token)
        
        for g in self.cache['iam']['list_users']:
            UserName = g['UserName']
            
            if self.check_cache('iam','list_user_policies',UserName,[]):
                self.cache['iam']['list_user_policies'][UserName] = iam.list_user_policies(UserName = UserName)['PolicyNames']

    def iam_list_attached_group_policies(self):
        self.iam_list_groups()

        
        iam = boto3.client('iam',
            aws_access_key_id		= self.aws_access_key_id,
            aws_secret_access_key	= self.aws_secret_access_key,
            aws_session_token		= self.aws_session_token)
        
        for g in self.cache['iam']['list_groups']:
            GroupName = g['GroupName']
            if self.check_cache('iam','list_attached_group_policies',GroupName,[]):
                self.cache['iam']['list_attached_group_policies'][GroupName] = iam.list_attached_group_policies(GroupName = GroupName)['AttachedPolicies']
                self.write_json()
    
    def iam_list_users(self):
        if self.check_cache('iam','list_users',None,{}):
            self.cache['iam']['list_users'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token).list_users()['Users']
            self.write_json()

    def iam_get_account_authorization_details(self):
        if self.check_cache('iam','get_account_authorization_details',None,[]):
            self.cache['iam']['get_account_authorization_details'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token).get_account_authorization_details() #['Users']         
            self.write_json()
 
    def iam_credentials(self):
        if self.check_cache('iam','credentials',None,{}):
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
            self.write_json()

    def rds_describe_db_instances(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('rds','describe_db_instances',region,{}):
                for db in boto3.client('rds',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).describe_db_instances().get('DBInstances'):
                    print(' - ' + db['DbiResourceId'])
                    self.cache['rds']['describe_db_instances'][region].append(db)
                self.write_json()

    def cloudtrail_describe_trails(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('cloudtrail','describe_trails',region,[]):
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
                    self.write_json()

    def cloudwatch_describe_alarms(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('cloudwatch','describe_alarms',region,[]):
                paginator = boto3.client('cloudwatch',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token).get_paginator('describe_alarms')

                for p in paginator.paginate():
                    for m in p['MetricAlarms']:
                        self.cache['cloudwatch']['describe_alarms'][region].append(m)
                self.write_json()

    def logs_describe_metric_filters(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('logs','describe_metric_filters',region,[]):
                paginator = boto3.client('logs',
                    region_name				= region,
                    aws_access_key_id		= self.aws_access_key_id,
                    aws_secret_access_key	= self.aws_secret_access_key,
                    aws_session_token		= self.aws_session_token
                ).get_paginator('describe_metric_filters')
                
                for p in paginator.paginate():
                    for cl in p['metricFilters']:
                        self.cache['logs']['describe_metric_filters'][region].append(cl)
                self.write_json()

                    
    def sns_list_topics(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('sns','list_topics',region,[]):
                for p in boto3.client('sns',
                            region_name				= region,
                            aws_access_key_id		= self.aws_access_key_id,
                            aws_secret_access_key	= self.aws_secret_access_key,
                            aws_session_token		= self.aws_session_token
                        ).get_paginator('list_topics').paginate():
                
                    for t in p['Topics']:
                        self.cache['sns']['list_topics'][region].append(t)
                self.write_json()

    def lambda_list_functions(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('lambda','list_functions',region,[]):
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
                self.write_json()
                        
    def iam_list_policies(self):
        if self.check_cache('iam','list_policies',None,[]):
            self.cache['iam']['list_policies'] = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
            ).list_policies()['Policies']
            self.write_json()

    def iam_get_policy(self):
        self.iam_list_policies()
        
        iam = boto3.client('iam',
                aws_access_key_id		= self.aws_access_key_id,
                aws_secret_access_key	= self.aws_secret_access_key,
                aws_session_token		= self.aws_session_token
        )
        
        for p in self.cache['iam']['list_policies']:
            PolicyName = p['PolicyName']    
            if self.check_cache('iam','get_policy_version',PolicyName,[]):
                # todo - confirm if this thing wants the policy name, or the policy arn
                self.cache['iam']['get_policy_version'][p['PolicyName']] = iam.get_policy_version(PolicyArn = p['Arn'], VersionId = p['DefaultVersionId'])['PolicyVersion']
            self.write_json()
                
    def guardduty_list_detectors(self):
        for region in self.ec2_describe_regions():
            if self.check_cache('guardduty','list_detectors',region,[]):

                for p in boto3.client('guardduty',
                        region_name				= region,
                        aws_access_key_id		= self.aws_access_key_id,
                        aws_secret_access_key	= self.aws_secret_access_key,
                        aws_session_token		= self.aws_session_token
                ).get_paginator('list_detectors').paginate():
                    for i in p['DetectorIds']:
                        self.cache['guardduty']['list_detectors'][region].append(i)
                        print(' - ' + i)
                self.write_json()

        