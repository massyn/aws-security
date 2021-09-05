import boto3
from botocore.config import Config
import datetime as dt
import dateutil.parser
from datetime import datetime
import csv
import time
import json
import os.path
from urllib.parse import urlparse

class collector:
   def __init__(self,aws_access_key_id = None,aws_secret_access_key = None,aws_session_token = None):
      # we need to pull the access keys into the class... this is used all the time
      self.aws_access_key_id      = aws_access_key_id
      self.aws_secret_access_key  = aws_secret_access_key
      self.aws_session_token      = aws_session_token
      self.cache = {}
      self.data_file = None
      self.counter = 0
      self.errors = 0
      self.start_time = time.time()

   def convert_timestamp(self,item_date_object):
      if isinstance(item_date_object, (dt.date,dt.datetime)):
         return item_date_object.timestamp()

   def checkVersion(self,xi):
      def cv_a(z,t):
         v = int(z[t] if t < len(z) else 0)
         m = 1000 ** (4 - t)
         return v * m

      b = boto3.__version__.split('.')
      x = xi.split('.')

      bv = cv_a(b,0) + cv_a(b,1) + cv_a(b,2) + cv_a(b,3)
      xv = cv_a(x,0) + cv_a(x,1) + cv_a(x,2) + cv_a(x,3)

      return bv >= xv           

   def write_json(self,action = False):
      if self.data_file:
         if action or not 's3:' in self.data_file:
            account = self.cache.get('sts',{}).get('get_caller_identity',{})['us-east-1']['Account']
                
            if account != {}:
               datestamp = datetime.now().strftime("%Y-%m-%d")
               output = self.data_file.replace('%a',account).replace('%d',datestamp)
               print(' -- writing json file -- '+ output)

               # -- is this s3?
               if 's3://' in output:
                  
                  p = urlparse(output, allow_fragments=False)
                  bucket = p.netloc
                  if p.query:
                     key = p.path.lstrip('/') + '?' + p.query
                  else:
                     key = p.path.lstrip('/')
                  
                  # TODO = s3 authentication will be tricky -- think about this for a sec...
                  boto3.client('s3').put_object(Body=json.dumps(self.cache,indent = 4, default=self.convert_timestamp), Bucket=bucket, Key=key)
                  
               else:
                  with open(output,'wt') as f:
                     f.write(json.dumps(self.cache,indent = 4, default=self.convert_timestamp))
                     f.close()
            else:
               print(' unable to write json until we have credentials ')

   def read_json(self,fi):
      if 'sts' in self.cache:
         account = self.cache['sts']['get_caller_identity']['us-east-1']['Account']
      else:
         account = ''
         if '%a' in fi:
               print('ERROR - we cannot read a file with %a if we don\'t know what the account is')
               exit(1)

      datestamp = datetime.now().strftime("%Y-%m-%d")
      f = fi.replace('%a',account).replace('%d',datestamp)

      self.data_file = f

      print(' -- loading ' + f)
      # -- is this s3?
      if 's3://' in f:
         p = urlparse(f, allow_fragments=False)
         bucket = p.netloc
         if p.query:
            key = p.path.lstrip('/') + '?' + p.query
         else:
            key = p.path.lstrip('/')

         try:
            self.cache = json.load(boto3.client('s3').get_object(Bucket=bucket, Key=key)['Body'])
         except:
            print(' ** Unable to read the s3 file - ' + f)
            return {}
      else:
         if os.path.isfile(f):
            with open(f,'rt') as j:
               self.cache = json.load(j)
               j.close()
         else:
            print(' !! cannot load ' + f)
            return {}

   def cache_call(self,client,function,region = 'us-east-1',parameter = {}, identifier = None):
      if not client in self.cache:
         self.cache[client] = {}
      if not function in self.cache[client]:
         self.cache[client][function] = {}

      if type(region) == list:
         regionList = region
         result = {}
         for region in regionList:
            self.cache_call(client,function,region,parameter,identifier)

         return self.cache[client][function]

      if identifier != None:
         if region not in self.cache[client][function]:
            self.cache[client][function][region] = {}
         if not identifier in self.cache[client][function][region]:
            z = self.aws_call(client,function,region,parameter)
            self.cache[client][function][region][identifier] = z
            self.write_json()
         return self.cache[client][function][region][identifier]

      else:
         if region not in self.cache[client][function]:
            z = self.aws_call(client,function,region,parameter)
            self.cache[client][function][region] = z
            self.write_json()
         return self.cache[client][function]

   def aws_call(self,client,function,region = 'us-east-1',parameter = {}):
      """
         This function only makes a call to AWS, and return the data - no processing at all.
         client
         function
         region
         parameter
      """

      self.counter += 1
      print('===========================================================================================')
      print('aws call - {client} / {function} - {region} - ({elapsed} seconds, {counter} API calls, {errors} errors)'.format(client = client,function = function, region = region, counter = self.counter, elapsed = int(time.time() - self.start_time), errors = self.errors))
      c = boto3.client( client ,
            aws_access_key_id		   = self.aws_access_key_id,
            aws_secret_access_key   = self.aws_secret_access_key,
            aws_session_token       = self.aws_session_token,
            region_name             = region,
            config                  = Config(connect_timeout=5, read_timeout=60, retries={'max_attempts': 5})
      )
      if c.can_paginate(function):
         output = []
         try:
            for a in c.get_paginator(function).paginate(**parameter):
               output.append(a)
         except Exception as e:
            print(' ----------------------------------------------------------------------------------------')
            print(' ** AWS ERROR ** ' + str(e))
            print(' ----------------------------------------------------------------------------------------')
            output.append( { '_exception' : str(e) })
            self.errors += 1
            if 'ThrottlingException' in str(e):
               print(' ** sleeping for 10 seconds, then try again **')
               time.sleep(10)
               return self.aws_call(client,function,region,parameter)

            if 'ExpiredToken' in str(e):
               self.write_json()
               exit(1)

         return output
      else:
         # -- convert the parameters
         para = ''
         for k in parameter:
            if(type(parameter[k]) == list):
               para += k + ' = ['
               toggle = False
               
               for v in parameter[k]:
                  if toggle:
                     para += ','
                  para += '\'' + v + '\''
                  toggle = True
               para += ']'
            else:
               para += k + ' = \'' + parameter[k] + '\','
         result = {}
         try:
            result = eval('c.' + function + '(' + para + ')')
         except Exception as e:
            print(' ----------------------------------------------------------------------------------------')
            print(' ** AWS ERROR ** ' + str(e))
            print(' ----------------------------------------------------------------------------------------')
            if 'ThrottlingException' in str(e):
               print(' ** sleeping for 10 seconds, then try again **')
               time.sleep(10)
               return self.aws_call(client,function,region,parameter)
               
            if 'ExpiredToken' in str(e):
               self.write_json()
               exit(1)

            result = { '_exception' : str(e) }
            self.errors += 1
         return result

   def collect_all(self,regions):
      print('*** COLLECTOR ***')
      
      # == Startup
      self.cache_call('sts','get_caller_identity')
      self.cache_call('iam','generate_credential_report')
      r = self.cache_call('ec2','describe_regions')

      core_regionList = sorted([x['RegionName'] for x in r['us-east-1']['Regions']])
      if regions == None:
         regionList = core_regionList
      else:
         regionList = [ 'us-east-1' ]  # us-east-1 must always be included - it contains our core IAM functions.

         for r in regions.split(','):
            if r in core_regionList and r not in regionList:   # it's a valid region, and not added yet
               regionList.append(r)
            else:
               print('WARNING - invalid region specified - ' + r)

      # == Access Analyzer
      self.cache_call('accessanalyzer','list_analyzers',regionList)
      
      # == API Gateway
      x = self.cache_call('apigateway','get_domain_names',regionList)
      for region in x:
         for r in x[region]:
            for i in r['items']:
               self.cache_call('apigateway','get_base_path_mappings', region, { 'domainName' : i['domainName']}, i['domainName'])

      x = self.cache_call('apigateway','get_rest_apis',regionList)
      for region in x:
         for r in x[region]:
            for i in r['items']:
               self.cache_call('apigateway','get_stages',region, { 'restApiId' : i['id' ]},i['id'])

               # TODO - something is a bit broken with the get_method function
               resources = self.cache_call('apigateway','get_resources',region,{ 'restApiId' : i['id' ]},i['id'])
               #root_id = [resource for resource in resources if resource["path"] == "/"][0]["id"]
               #for r in resources:
               #   for s in r['items']:
               #      if s['path'] == '/':       
               #         self.cache_call('apigateway','get_method',region,{ 'restApiId' : i['id' ], 'resourceId' : s['id'], 'httpMethod' : 'GET'},i['id'])

      self.cache_call('apigateway','get_client_certificates',regionList)
      
      # == Auto scaling
      self.cache_call('autoscaling','describe_auto_scaling_groups',regionList)
      self.cache_call('autoscaling','describe_launch_configurations',regionList)

      # == ACM
      x = self.cache_call('acm','list_certificates',regionList)
      for region in x:
         for r in x[region]:
            for cert in r['CertificateSummaryList']:
               self.cache_call('acm','describe_certificate',region,{ 'CertificateArn' : cert['CertificateArn']},cert['CertificateArn'])
      
      # == Cloudformation
      self.cache_call('cloudformation','describe_stacks',regionList)
      
      # == Cloudfront
      self.cache_call('cloudfront','list_distributions',regionList)
      self.cache_call('cloudfront','list_cloud_front_origin_access_identities',regionList)
      self.cache_call('cloudfront','list_streaming_distributions',regionList)
      if self.checkVersion('1.17.101'):
         self.cache_call('cloudfront','list_functions',regionList)
      else:
         print(' ** YOU SHOULD UPGRADE BOTO3 TO THE LATEST VERSION!! **')
      
      # == Cloudsearch
      self.cache_call('cloudsearch','describe_domains')
      
      # == CloudTrail
      self.cache_call('cloudtrail','list_trails',regionList)
      t = self.cache_call('cloudtrail','describe_trails',regionList)
      for region in t:
         for trail in t[region]['trailList']:
            self.cache_call('cloudtrail','get_trail_status',region,{ 'Name' : trail['TrailARN'] },trail['TrailARN'])
            self.cache_call('cloudtrail','get_event_selectors',region,{ 'TrailName' : trail['TrailARN'] },trail['TrailARN'])
            
      # == Cloudwatch
      self.cache_call('cloudwatch','describe_alarms',regionList)
      
      # == Cognito
      x = self.cache_call('cognito-identity','list_identity_pools',regionList, { 'MaxResults' : 60 })
      for region in x:
         for j in x[region]:
            for i in j.get('IdentityPools',[]):
               self.cache_call('cognito-identity','describe_identity_pool',region, { 'IdentityPoolId ' : i['IdentityPoolId'] }, i['IdentityPoolId'])

      x = self.cache_call('cognito-idp','list_user_pools',regionList, { 'MaxResults' : 60 })
      for region in x:
         for j in x[region]:
            for i in j.get('UserPools',[]):
               self.cache_call('cognito-idp','describe_user_pool',region, { 'UserPoolId' : i['Id'] }, i['Id'])
            
      # == Config
      self.cache_call('config','describe_configuration_recorders',regionList)
      self.cache_call('config','describe_configuration_recorder_status',regionList)
      
      x = self.cache_call('config','describe_delivery_channels',regionList)
      for region in x:
         for d in x[region]['DeliveryChannels']:
            self.cache_call('config','describe_delivery_channel_status',region,{ 'DeliveryChannelNames' : [ d['name'] ] },d['name'])
      
      # == Directory services
      self.cache_call('ds','describe_directories',regionList)
      
      # == Direct Connect
      x = self.cache_call('directconnect','describe_connections',regionList)
      for region in x:
         for c in x[region]['connections']:
            self.cache_call('directconnect','describe_direct_connect_gateways',region,{ 'directConnectGatewayId' : c['connectionId']},c['connectionId'])
            self.cache_call('directconnect','describe_virtual_interfaces',region,{ 'directConnectGatewayId' : c['connectionId']},c['connectionId'])

      # == DMS
      self.cache_call('dms','describe_certificates',regionList)
      self.cache_call('dms','describe_endpoints',regionList)
      self.cache_call('dms','describe_replication_instances',regionList)
      
      # == DynamoDb
      x = self.cache_call('dynamodb','list_tables',regionList)
      for region in x:
         for d in x[region]:
            for tableName in d['TableNames']:
               self.cache_call('dynamodb','describe_table',region,{'TableName' : tableName},tableName)
      
      # == EC2
      self.cache_call('ec2','describe_instances',regionList)
      self.cache_call('ec2','describe_account_attributes',regionList)
      self.cache_call('ec2','describe_images',regionList, { 'Owners ' : [ 'self' ] })
      self.cache_call('ec2','describe_regions')
      self.cache_call('ec2','describe_security_groups',regionList)
      self.cache_call('ec2','describe_network_acls',regionList)
      self.cache_call('ec2','describe_vpcs',regionList)
      self.cache_call('ec2','describe_route_tables',regionList)
      self.cache_call('ec2','describe_subnets',regionList)
      self.cache_call('ec2','describe_flow_logs',regionList)
      self.cache_call('ec2','describe_iam_instance_profile_associations',regionList)
      self.cache_call('ec2','describe_internet_gateways',regionList)
      self.cache_call('ec2','describe_nat_gateways',regionList)
      self.cache_call('ec2','describe_snapshots',regionList,{ 'OwnerIds' : [ 'self' ] })
      self.cache_call('ec2','describe_vpc_peering_connections',regionList)
      self.cache_call('ec2','describe_network_interfaces',regionList)
      self.cache_call('ec2','describe_key_pairs',regionList)
      self.cache_call('ec2','describe_volumes',regionList)
      self.cache_call('ec2','describe_moving_addresses',regionList)
      self.cache_call('ec2','describe_vpc_endpoints',regionList)
      self.cache_call('ec2','get_ebs_encryption_by_default',regionList)
      self.cache_call('ec2','describe_vpn_connections',regionList)
      self.cache_call('ec2','describe_vpn_gateways',regionList)
      self.cache_call('ec2','describe_dhcp_options',regionList)
      self.cache_call('ec2','describe_managed_prefix_lists',regionList)
      self.cache_call('ec2','describe_transit_gateways',regionList)
      self.cache_call('ec2','describe_transit_gateway_attachments',regionList)

      # == ECR
      x = self.cache_call('ecr','describe_repositories',regionList)
      for region in x:
         for z in x[region]:
            for r in z['repositories']:
               self.cache_call('ecr','get_repository_policy',region, { 'repositoryName' : r['repositoryName'] , 'registryId' : r['registryId']}, r['repositoryName'])
               self.cache_call('ecr','describe_images',region,{'repositoryName' : r['repositoryName']},r['repositoryName'])
      
      # == ECS
      x = self.cache_call('ecs','list_clusters',regionList)
      for region in x:
         for d in x[region]:
            for c in d['clusterArns']:
               for z in self.cache_call('ecs','list_services',region,{'cluster' : c},c):
                  for i in z['serviceArns']:
                     self.cache_call('ecs','describe_services',region,{ 'cluster' : c, 'services' :  [i]  },i)

                  for i in self.cache_call('ecs','list_container_instances',region,{'cluster' : c})[region]:
                     for z in i['containerInstanceArns']:
                        self.cache_call('ecs','describe_container_instances',region,{ 'cluster' : c, 'containerInstances' :  [z]   },z)

      x = self.cache_call('ecs','list_task_definitions',regionList)
      for region in x:
         for z in x[region]:
            for t in z['taskDefinitionArns']:
               self.cache_call('ecs','describe_task_definition',region,{'taskDefinition' : t},t)

      # == EFS
      x = self.cache_call('efs','describe_file_systems',regionList)
      
      for region in x:
         for z in x[region]:
            for f in z['FileSystems']:
               self.cache_call('efs','describe_mount_targets',region,{'FileSystemId' : f['FileSystemId']},f['FileSystemId'])

      # == ElasticBeanstalk
      self.cache_call('elasticbeanstalk','describe_applications',regionList)
      x = self.cache_call('elasticbeanstalk','describe_environments',regionList)
      for region in x:
         for a in x[region]:
            for b in a['Environments']:
               self.cache_call('elasticbeanstalk','describe_configuration_settings',region,{ 'ApplicationName' : b['ApplicationName'], 'EnvironmentName' : b['EnvironmentName']}, b['ApplicationName'])

      # == Elasticache
      self.cache_call('elasticache','describe_cache_engine_versions',regionList)
      self.cache_call('elasticache','describe_cache_clusters',regionList)
      self.cache_call('elasticache','describe_replication_groups',regionList)
      self.cache_call('elasticache','describe_reserved_cache_nodes',regionList)
      self.cache_call('elasticache','describe_cache_subnet_groups',regionList)
      self.cache_call('elasticache','describe_snapshots',regionList)

      # == ElastiSearch
      x = self.cache_call('es','list_domain_names',regionList)
      for region in x:
         for y in x[region]['DomainNames']:
            self.cache_call('es','describe_elasticsearch_domain',region,{'DomainName' : y['DomainName']},y['DomainName'])

      # == ELB
      self.cache_call('elb','describe_load_balancers',regionList)
      
      # == ELBv2
      e = self.cache_call('elbv2','describe_ssl_policies',regionList)
      e = self.cache_call('elbv2','describe_load_balancers',regionList)
      for region in e:
         for x in e[region]:
            for elb in x['LoadBalancers']:
               self.cache_call('elbv2','describe_listeners',region,{ 'LoadBalancerArn' : elb['LoadBalancerArn'] },elb['LoadBalancerArn'])
               self.cache_call('elbv2','describe_target_groups',region,{ 'LoadBalancerArn' : elb['LoadBalancerArn'] },elb['LoadBalancerArn'])
      
      # == EKS
      x = self.cache_call('eks','list_clusters',regionList)
      for region in x:
         for e in x[region]:
            for cluster in e['clusters']:
               self.cache_call('eks','describe_cluster',region,{ 'name' : cluster},cluster)
               for f in self.cache_call('eks','list_fargate_profiles',region,{'clusterName' : cluster},cluster):
                  for fargateProfileName in f['fargateProfileNames']:
                     self.cache_call('eks','describe_fargate_profile',region,{ 'clusterName' : e, 'fargateProfileName' : fargateProfileName},fargateProfileName)
      
      # == EMR
      self.cache_call('emr','get_block_public_access_configuration',regionList)
      x = self.cache_call('emr','list_clusters',regionList)
      for region in x:
         for e in x[region]:
            for cluster in e['Clusters']:
               self.cache_call('emr','list_instances',regionList, {'ClusterId' : cluster['Id']})
               self.cache_call('emr','describe_cluster',regionList, {'ClusterId' : cluster['Id']})

      # == Glacier
      x = self.cache_call('glacier','list_vaults',regionList)
      for region in x:
         for g in x[region]:
            for v in g['VaultList']:
               self.cache_call('glacier','get_vault_access_policy',region,{ 'vaultName' : v['VaultName'] } , v['VaultName'])
               self.cache_call('glacier','get_vault_lock',region,{ 'vaultName' : v['VaultName'] } , v['VaultName'])

      # == GuardDuty
      self.cache_call('guardduty','list_detectors',regionList)
      
      # == IAM Policies
      x = self.cache_call('iam','list_policies')
      for region in x:
         for z in x[region]:
            for p in z['Policies']:
               self.cache_call('iam','get_policy_version',region,{ 'PolicyArn' : p['Arn'] , 'VersionId' : p['DefaultVersionId'] } ,p['PolicyName'])

      # == IAM
      self.cache_call('iam','list_server_certificates')
      self.cache_call('iam','list_virtual_mfa_devices')
      self.cache_call('iam','get_account_summary')
      self.cache_call('iam','get_account_authorization_details')
      x = self.cache_call('iam','list_saml_providers')
      for region in x:
         for s in x[region]['SAMLProviderList']:
            self.cache_call('iam','get_saml_provider',region,{'SAMLProviderArn' : s['Arn']})

      if not 'AccountPasswordPolicy' in self.cache['iam']:
         self.cache['iam']['AccountPasswordPolicy'] = {}
         self.cache['iam']['AccountPasswordPolicy']['us-east-1'] = self.iam_AccountPasswordPolicy()
         self.write_json()
      
      # == IAM Groups
      x = self.cache_call('iam','list_groups')
      for region in x:
         for GG in x[region]:
            for g in GG['Groups']:
               self.cache_call('iam','get_group',region,{'GroupName' : g['GroupName'] },g['GroupName'])
               self.cache_call('iam','list_attached_group_policies',region,{'GroupName' : g['GroupName']},g['GroupName'])
               
               for p in self.cache_call('iam','list_group_policies',region,{'GroupName' : g['GroupName'] },g['GroupName']):
                  for PolicyName in p['PolicyNames']:
                     self.cache_call('iam','get_group_policy',region,{'GroupName' : g['GroupName'],'PolicyName' : PolicyName } , g['GroupName'] + ':' + PolicyName)
         
      # == IAM Users
      x = self.cache_call('iam','list_users')
      for region in x:
         for UU in x[region]:
            for u in UU['Users']:
               self.cache_call('iam','list_mfa_devices',region,{'UserName' : u['UserName'] } ,u['UserName'])
               self.cache_call('iam','list_ssh_public_keys',region,{'UserName' : u['UserName'] } ,u['UserName'])
               self.cache_call('iam','list_access_keys',region,{'UserName' : u['UserName'] } ,u['UserName'])
               self.cache_call('iam','list_attached_user_policies',region,{'UserName' : u['UserName'] } ,u['UserName'])
               for p in self.cache_call('iam','list_user_policies',region,{'UserName' : u['UserName'] },u['UserName']):
                  for PolicyName in p['PolicyNames']:
                     self.cache_call('iam','get_user_policy',region,{'UserName' : u['UserName'],'PolicyName' : PolicyName } , u['UserName'] + ':' + PolicyName)

      if not 'get_credential_report' in self.cache['iam']:
         self.cache['iam']['get_credential_report'] = {}
         self.cache['iam']['get_credential_report']['us-east-1'] = self.iam_get_credential_report()
         self.write_json()

      # == IAM Roles         
      x = self.cache_call('iam','list_roles')
      for region in x:
         for RR in x[region]:
            for u in RR['Roles']:
               self.cache_call('iam','list_attached_role_policies',region,{'RoleName' : u['RoleName'] },u['RoleName'])
               for p in self.cache_call('iam','list_role_policies',region,{'RoleName' : u['RoleName'] },u['RoleName']):
                  for PolicyName in p['PolicyNames']:
                     self.cache_call('iam','get_role_policy',region,{'RoleName' : u['RoleName'],'PolicyName' : PolicyName } , u['RoleName'] + ':' + PolicyName)         
      # == KMS
      k = self.cache_call('kms','list_keys',regionList)
      for region in k:
         for KK in k[region]:
            for key in KK['Keys']:
               self.cache_call('kms','get_key_rotation_status',region,{'KeyId' : key['KeyId'] } , key['KeyId'])
      
      # == Lambda
      self.cache_call('lambda','list_functions',regionList)
      
      # == Logs
      self.cache_call('logs','describe_metric_filters',regionList)
      self.cache_call('logs','describe_log_groups',regionList)
      
      # == MQ
      x = self.cache_call('mq','list_brokers',regionList)
      for region in x:
         for z in x[region]:
            for i in z['BrokerSummaries']:
               self.cache_call('mq','describe_broker',region,{ 'BrokerId' : i['BrokerId'] },i['BrokerId'])
      
      # == Organizations
      self.cache_call('organizations','describe_organization')
      # -- only run this if you are the master account
      if 'describe_organization' in self.cache['organizations']:
         if self.cache['sts']['get_caller_identity']['us-east-1']['Account'] == self.cache['organizations']['describe_organization']['us-east-1'].get('Organization',{}).get('MasterAccountId',{}):
            self.cache_call('organizations','list_accounts')
      
      # == RDS
      self.cache_call('rds','describe_db_instances',regionList)
      self.cache_call('rds','describe_db_snapshots',regionList)
      self.cache_call('rds','describe_event_subscriptions',regionList)
      self.cache_call('rds','describe_db_cluster_snapshots',regionList)
      self.cache_call('rds','describe_db_clusters',regionList)
      self.cache_call('rds','describe_db_parameter_groups',regionList)

      # == Route 53
      self.cache_call('route53','list_hosted_zones')
      self.cache_call('route53domains','list_domains')
      
      # == S3
      x = self.cache_call('s3','list_buckets')
      for region in x:
         for s in x[region]['Buckets']:
            self.cache_call('s3','get_bucket_logging',region,{'Bucket' : s['Name']},s['Name'])
            self.cache_call('s3','get_bucket_versioning',region,{'Bucket' : s['Name']},s['Name'])
            self.cache_call('s3','get_bucket_policy',region,{'Bucket' : s['Name']},s['Name'])
            self.cache_call('s3','get_bucket_encryption',region,{'Bucket' : s['Name']},s['Name'])
            self.cache_call('s3','get_bucket_acl',region,{'Bucket' : s['Name']},s['Name'])
            self.cache_call('s3','get_public_access_block',region,{'Bucket' : s['Name']},s['Name'])
            x = self.cache_call('s3','get_bucket_location',region,{'Bucket' : s['Name']},s['Name'])
            if x['LocationConstraint'] != None:
               self.cache_call('s3control','list_access_points',x['LocationConstraint'],{ 'AccountId' : self.cache['sts']['get_caller_identity']['us-east-1']['Account'],'Bucket' : s['Name']},s['Name'])
    
         if not '_public_s3_bucket' in self.cache['s3']:
            self.cache['s3']['_public_s3_bucket'] = {}
         if not region in self.cache['s3']['_public_s3_bucket']:
            self.cache['s3']['_public_s3_bucket'][region] = {}
         if not s['Name'] in self.cache['s3']['_public_s3_bucket'][region]:
            self.cache['s3']['_public_s3_bucket'][region][s['Name']] = self.check_if_S3_bucket_is_public(s['Name'])
      
      # -- check the CloudTrail S3 buckets
      for region in self.cache['cloudtrail']['describe_trails']:
         for ct in self.cache['cloudtrail']['describe_trails'][region]:
            if 'S3BucketName' in ct:
               if not ct['S3BucketName'] in self.cache['s3']['_public_s3_bucket'][region]:
                  self.cache['s3']['_public_s3_bucket'][region][ct['S3BucketName']] = self.check_if_S3_bucket_is_public(ct['S3BucketName'])
      
      # == Sagemaker
      x = self.cache_call('sagemaker','list_notebook_instances',regionList)
      for region in x:
         for z in x[region]:
            for i in z.get('NotebookInstances',[]):
               self.cache_call('sagemaker','describe_notebook_instance',region,{ 'NotebookInstanceName' : i['NotebookInstanceName']},i['NotebookInstanceName'])
            
      x = self.cache_call('sagemaker','list_endpoints',regionList)
      for region in x:
         for z in x[region]:
            for i in z.get('Endpoints',[]):
               self.cache_call('sagemaker','describe_endpoints',region,{ 'EndpointName' : x['EndpointName']},x['EndpointName'])

      # == SecretsManager
      x = self.cache_call('secretsmanager','list_secrets',regionList)
      for region in x:
         for y in x[region]:
            for s in y['SecretList']:
               self.cache_call('secretsmanager','describe_secret',region, {'SecretId' : s['ARN']}, s['ARN'])
      
      # == SNS
      x = self.cache_call('sns','list_subscriptions',regionList)
      for region in x:
         for y in x[region]:
            for t in y['Subscriptions']:
               self.cache_call('sns','get_subscription_attributes',region,{ 'SubscriptionArn' : t['SubscriptionArn']} ,t['SubscriptionArn'])

      x = self.cache_call('sns','list_topics',regionList)
      for region in x:
         for y in x[region]:
            for t in y['Topics']:
               self.cache_call('sns','list_subscriptions_by_topic',region,{'TopicArn' : t['TopicArn']},t['TopicArn'])
               self.cache_call('sns','get_topic_attributes',region,{'TopicArn' : t['TopicArn']},t['TopicArn'])
      self.cache_call('sns','list_platform_applications',regionList)

      # == SQS
      x = self.cache_call('sqs','list_queues',regionList)
      for region in x:
         for y in x[region]:
            for t in y.get('QueueUrls',[]):

               self.cache_call('sqs','get_queue_attributes',region,{ 'QueueUrl' : t },t)

      # == SSM
      self.cache_call('ssm','describe_instance_information',regionList)
      self.cache_call('ssm','get_parameters_by_path',regionList,{'Path' : '/', 'Recursive' : True})
      
      # 2021.06.27 - Disabling the ssm list_documents piece because, man, it takes a long time to run...  If we really need it,
      # we can turn it back on (or find another way)
      #x = self.cache_call('ssm','list_documents',regionList)
      #for region in x:
      #   for z in x[region]:
      #      for y in z['DocumentIdentifiers']:
      #         self.cache_call('ssm','describe_document',region, {'Name' : y['Name']}, y['Name'])

      # == SSO
      x = self.cache_call('sso-admin','list_instances',regionList)
      for region in x:
         for y in x[region]:
            for t in y.get('Instances',[]):
               p = self.cache_call('sso-admin','list_permission_sets',region,{'InstanceArn' : t['InstanceArn']},t['InstanceArn']) #[region]

               # This is a work in progress - I need to fix up the parsing of the multi-layer parameters.
               self.cache_call('identitystore','list_users',region,{'IdentityStoreId' : t['IdentityStoreId'], 'Filters' : [{ 'AttributePath' : 'UserName','AttributeValue': '' }] }, t['IdentityStoreId'])
               
               for q in p:
                  for ps in q['PermissionSets']:
                     self.cache_call('sso-admin','describe_permission_set',region,{'InstanceArn' : t['InstanceArn'], 'PermissionSetArn' : ps} ,ps)
                     self.cache_call('sso-admin','get_inline_policy_for_permission_set',region,{'InstanceArn' : t['InstanceArn'], 'PermissionSetArn' : ps},ps)
                     self.cache_call('sso-admin','list_managed_policies_in_permission_set',region,{'InstanceArn' : t['InstanceArn'], 'PermissionSetArn' : ps},ps)
                     
                     a = self.cache_call('sso-admin','list_accounts_for_provisioned_permission_set',region,{'InstanceArn' : t['InstanceArn'], 'PermissionSetArn' : ps},ps)

                     for h in a:
                        for aid in h['AccountIds']:
                           self.cache_call('sso-admin','list_account_assignments',region,{'InstanceArn' : t['InstanceArn'], 'PermissionSetArn' : ps, 'AccountId' : aid},ps + '/' + aid)
                           

               


      # == WAF (Global) - Classic
      x = self.cache_call('waf','list_web_acls')
      for region in x:
         for z in x[region]:
            for w in z['WebACLs']:
               for r in self.cache_call('waf','get_web_acl',region,{ 'WebACLId' : w['WebACLId']}, w['WebACLId'])['WebACL']['Rules']:
                  self.cache_call('waf','get_rule',region,{ 'RuleId' : r['RuleId']}, r['RuleId'])
      
      x = self.cache_call('waf','list_rules')
      for region in x:
         for z in x[region]:
            for w in z['Rules']:
               self.cache_call('waf','get_rule',region,{'RuleId' : w['RuleId'] }, w['RuleId'] )

      # == WAF (Regional) - Classic
      x = self.cache_call('waf-regional','list_web_acls',regionList)
      for region in x:
         for w in x[region]['WebACLs']:
            for r in self.cache_call('waf-regional','get_web_acl',region,{ 'WebACLId' : w['WebACLId']}, w['WebACLId'])['WebACL']['Rules']:
               self.cache_call('waf-regional','get_rule',region,{ 'RuleId' : r['RuleId']}, r['RuleId'])
            
            a = self.cache_call('waf-regional','list_resources_for_web_acl',region,{ 'WebACLId' : w['WebACLId']}, w['WebACLId'])
            for ResourceArn in a['ResourceArns']:
               self.cache_call('waf-regional','get_web_acl_for_resource',region, { 'ResourceArn' : ResourceArn }, ResourceArn)

      # == WAFv2
      self.cache_call('wafv2','list_web_acls',regionList,{'Scope' : 'REGIONAL' }, 'REGIONAL')
      self.cache_call('wafv2','list_web_acls','us-east-1',{'Scope' : 'CLOUDFRONT' }, 'CLOUDFRONT')

      self.write_json(True)
      # --------------------------------------------------------------

   def iam_get_credential_report(self):
      print('custom - iam_get_credential_report')
      def age(dte):
         if dte == 'not_supported' or dte == 'N/A' or dte == 'no_information':
            return -1
         else:
            result = dt.date.today() - dateutil.parser.parse(dte).date()
            return result.days
         
      iam = boto3.client('iam',
            aws_access_key_id		= self.aws_access_key_id,
            aws_secret_access_key	= self.aws_secret_access_key,
            aws_session_token		= self.aws_session_token,
            config=Config(connect_timeout=5, read_timeout=60, retries={'max_attempts': 20})
      )

      response = iam.generate_credential_report()
      while response['State'] != 'COMPLETE':
         time.sleep(2)
         response = iam.generate_credential_report()

      response = iam.get_credential_report()
      credential_report_csv = response['Content'].decode('utf-8')
      reader = csv.DictReader(credential_report_csv.splitlines())
      
      output = []
      for row in reader:
         row['_password_last_changed_age']		   = age(row['password_last_changed'])
         row['_password_last_used_age']			   = age(row['password_last_used'])
         row['_access_key_1_last_rotated_age']	   = age(row['access_key_1_last_rotated'])
         row['_access_key_1_last_used_date_age']	= age(row['access_key_1_last_used_date'])
         row['_access_key_2_last_rotated_age']	   = age(row['access_key_2_last_rotated'])
         row['_access_key_2_last_used_date_age']   = age(row['access_key_2_last_used_date'])
         row['_user_creation_time_age']			   = age(row['user_creation_time'])
         output.append(row)
         
      return output
   
   def iam_AccountPasswordPolicy(self):
      print('custom - iam_AccountPasswordPolicy')
      output = {}
      try:
         response = boto3.resource('iam',
            aws_access_key_id		= self.aws_access_key_id,
            aws_secret_access_key	= self.aws_secret_access_key,
            aws_session_token		= self.aws_session_token
         ).AccountPasswordPolicy()

         output['max_password_age']                 = response.max_password_age
         output['minimum_password_length']          = response.minimum_password_length
         output['password_reuse_prevention']        = response.password_reuse_prevention
         output['allow_users_to_change_password']   = response.allow_users_to_change_password
         output['require_lowercase_characters']     = response.require_lowercase_characters
         output['require_numbers']                  = response.require_numbers
         output['require_symbols']                  = response.require_symbols
         output['require_uppercase_characters']     = response.require_uppercase_characters
      except:
         output['max_password_age']                 = 9999999
         output['minimum_password_length']          = 0
         output['password_reuse_prevention']        = 0
         output['allow_users_to_change_password']   = False
         output['require_lowercase_characters']     = False
         output['require_numbers']                  = False
         output['require_symbols']                  = False
         output['require_uppercase_characters']     = False
      return output
   
   def check_if_S3_bucket_is_public(self,bucket):
      print('custom - check if S3 bucket is public - ' + bucket)
      client = boto3.client('s3', aws_access_key_id='', aws_secret_access_key='')
      client._request_signer.sign = (lambda *args, **kwargs: None)
      
      result = {}
      
      # get_bucket_accelerate_configuration
      try:
         client.get_bucket_accelerate_configuration(Bucket=bucket)
         result['get_bucket_accelerate_configuration'] = True
      except:
         result['get_bucket_accelerate_configuration'] = False
         
      # get_bucket_acl
      try:
         client.get_bucket_acl(Bucket=bucket)
         result['get_bucket_acl'] = True
      except:
         result['get_bucket_acl'] = False
               
      # get_bucket_intelligent_tiering_configuration
      try:
         client.get_bucket_intelligent_tiering_configuration(Bucket=bucket)
         result['get_bucket_intelligent_tiering_configuration'] = True
      except:
         result['get_bucket_intelligent_tiering_configuration'] = False
               
      # get_bucket_location
      try:
         client.get_bucket_location(Bucket=bucket)
         result['get_bucket_location'] = True
      except:
         result['get_bucket_location'] = False
         
      # get_bucket_logging
      try:
         client.get_bucket_logging(Bucket=bucket)
         result['get_bucket_logging'] = True
      except:
         result['get_bucket_logging'] = False
               
      # get_bucket_notification
      try:
         client.get_bucket_notification(Bucket=bucket)
         result['get_bucket_notification'] = True
      except:
         result['get_bucket_notification'] = False
         
      # get_bucket_notification_configuration
      try:
         client.get_bucket_notification_configuration(Bucket=bucket)
         result['get_bucket_notification_configuration'] = True
      except:
         result['get_bucket_notification_configuration'] = False

      # get_bucket_request_payment
      try:
         client.get_bucket_request_payment(Bucket=bucket)
         result['get_bucket_request_payment'] = True
      except:
         result['get_bucket_request_payment'] = False
      
      # get_bucket_versioning
      try:
         client.get_bucket_versioning(Bucket=bucket)
         result['get_bucket_versioning'] = True
      except:
         result['get_bucket_versioning'] = False

         
      # list_bucket_analytics_configurations
      try:
         client.list_bucket_analytics_configurations(Bucket=bucket)
         result['list_bucket_analytics_configurations'] = True
      except:
         result['list_bucket_analytics_configurations'] = False
      
      # list_bucket_intelligent_tiering_configurations
      try:
         client.list_bucket_intelligent_tiering_configurations(Bucket=bucket)
         result['list_bucket_intelligent_tiering_configurations'] = True
      except:
         result['list_bucket_intelligent_tiering_configurations'] = False

      # list_multipart_uploads
      try:
         client.list_multipart_uploads(Bucket=bucket)
         result['list_multipart_uploads'] = True
      except:
         result['list_multipart_uploads'] = False
      
      # list_object_versions
      try:
         client.list_object_versions(Bucket=bucket)
         result['list_object_versions'] = True
      except:
         result['list_object_versions'] = False

      # list_objects
      try:
         client.list_objects(Bucket=bucket)
         result['list_objects'] = True
      except:
         result['list_objects'] = False

      # list_objects_v2
      try:
         client.list_objects_v2(Bucket=bucket)
         result['list_objects_v2'] = True
      except:
         result['list_objects_v2'] = False

      
      return result
   ##########################################################################################

def main():
   c = collector()
   file = 'c:/temp/output-%a.json'
   c.cache_call('sts','get_caller_identity')       # We do this one first, so we know what account we're talking about
   
   c.data_file = file
   c.read_json(file)
   
   c.collect_all()
   
if __name__ == '__main__':
   main()