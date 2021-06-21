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

   def convert_timestamp(self,item_date_object):
      if isinstance(item_date_object, (dt.date,dt.datetime)):
         return item_date_object.timestamp()
              
   def write_json(self,action = False):
      if self.data_file:
         if action or not 's3:' in self.data_file:
            account = self.cache.get('sts',{}).get('get_caller_identity',{}).get('Account',{})
                
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
         account = self.cache['sts']['get_caller_identity']['Account']
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

   def cache_call(self,pager,client,function,region = None, leaf = None,variable = None, parameter = {}, cacheleaf = None):
      if not client in self.cache:
         self.cache[client] = {}
         
      # -- identify field3
      field3 = None
      if region == None and cacheleaf != None:
         field3 = cacheleaf
      if region != None and cacheleaf == None:
         field3 = region     
      if region == '*':
         field3 = None
      
      if region != None and cacheleaf != None:
         if not function in self.cache[client]:
            self.cache[client][function] = {}
            
         if not region in self.cache[client][function]:
            self.cache[client][function][region] = {}
         
         if not cacheleaf in self.cache[client][function][region]:
            try:
               self.cache[client][function][region][cacheleaf] = self.aws_call(pager,client,function,region,leaf,variable,parameter)
            except:
               self.cache[client][function][region][cacheleaf] = False
            self.write_json()
            return self.cache[client][function][region][cacheleaf]
         else:
            return self.cache[client][function][region][cacheleaf]

      if region == None:
         if field3 == None:
            if function in self.cache[client]:
               return self.cache[client][function]
            else:
               self.cache[client][function] = self.aws_call(pager,client,function,'us-east-1',leaf,variable,parameter)
               self.write_json()
               return self.cache[client][function]
         else:
               if not function in self.cache[client]:
                  self.cache[client][function] = {}
               if field3 in self.cache[client][function]:
                  return self.cache[client][function][field3]
               else:
                  self.cache[client][function][field3] = self.aws_call(pager,client,function,'us-east-1',leaf,variable,parameter)
                  self.write_json()
                  return self.cache[client][function][field3]
      else:
         if region == '*':
            if not function in self.cache[client]:
               self.cache[client][function] = self.aws_call(pager,client,function,region,leaf,variable,parameter)
               self.write_json()
               return self.cache[client][function]
            else:
               return self.cache[client][function]
         else:
            if not function in self.cache[client]:
               self.cache[client][function] = {}
               
            if region in self.cache[client][function]:
               return self.cache[client][function][region]
            else:
               self.cache[client][function][region] = self.aws_call(pager,client,function,region,leaf,variable,parameter)
               self.write_json()
               return self.cache[client][function][region]

      return self.cache[client][function][region]

   def aws_call(self,pager,client,function,region = 'us-east-1', leaf = None,variable = None, parameter = {}):
      print('aws call - {client} / {function} ({region})'.format(client = client,function = function, region = region))

      # -- is this a global call (touch all regions)?
      if region == '*':
         output = {}
         for R in self.cache_call(False,'ec2','describe_regions',None,'Regions','RegionName'):
            output[R] = self.aws_call(pager,client,function,R,leaf,variable,parameter)
         return output
      
      else:
         # -- single call
         c = boto3.client( client ,
            aws_access_key_id		= self.aws_access_key_id,
            aws_secret_access_key	= self.aws_secret_access_key,
            aws_session_token		= self.aws_session_token,
            region_name             = region,
            config=Config(connect_timeout=5, read_timeout=60, retries={'max_attempts': 5})
         )
         
         if pager == False:
            
            # -- convert the parameters
            para = ''
            for k in parameter:
               para += k + ' = \'' + parameter[k] + '\','

            if leaf == None:
               result = eval('c.' + function + '(' + para + ')')
            else:
               try:
                  result = eval('c.' + function + '(' + para + ')')[leaf]
               except:
                  print(' ** AWS Call failed **')
                  result = {}
         else:
            output = []
            for p in c.get_paginator(function).paginate(**parameter):
               if leaf == None:
                  output.append(p)
               else:
                  for i in p[leaf]:
                     output.append(i)
                  
            return output
                        
         if variable == None:
            return result 
         else:
            return [x[variable] for x in result]
 
   def collect_all(self):
      print('*** COLLECTOR ***')
      
      # == Startup
      self.cache_call(False,'sts','get_caller_identity')       # We do this one first, so we know what account we're talking about
      self.cache_call(False,'iam','generate_credential_report')   # this report takes a while to run, so do it first
      
      # == Cloudfront
      self.cache_call(True,'cloudfront','list_distributions','*','DistributionList',None,{},None)
      self.cache_call(True,'cloudfront','list_cloud_front_origin_access_identities','*','CloudFrontOriginAccessIdentityList',None,{},None)
      self.cache_call(True,'cloudfront','list_streaming_distributions','*','StreamingDistributionList',None,{},None)
      self.cache_call(False,'cloudfront','list_functions','*','FunctionList',None,{},None)
      
      # == CloudTrail
      t = self.cache_call(False,'cloudtrail','describe_trails','*','trailList',None,{},None)
      for region in t:
         for trail in t[region]:
            self.cache_call(False,'cloudtrail','get_trail_status',region,None,None,{ 'Name' : trail['TrailARN'] },trail['TrailARN'])
            self.cache_call(False,'cloudtrail','get_event_selectors',region,None,None,{ 'TrailName' : trail['TrailARN'] },trail['TrailARN'])
            
      # == Cloudwatch
      self.cache_call(False,'cloudwatch','describe_alarms','*','MetricAlarms',None,{},None)
      
      # == Config
      self.cache_call(False,'config','describe_configuration_recorders','*','ConfigurationRecorders',None, {}, None)
      self.cache_call(False,'config','describe_configuration_recorder_status','*','ConfigurationRecordersStatus',None,{},None)
      
      # == DynamoDb
      self.cache_call(True,'dynamodb','list_tables','*','TableNames')
      
      # == EC2
      self.cache_call(False,'ec2','describe_regions',None,'Regions','RegionName', {} , None)
      self.cache_call(False,'ec2','describe_instances','*','Reservations','Instances', {}, None)
      self.cache_call(False,'ec2','describe_security_groups','*','SecurityGroups',None,{},None)
      self.cache_call(False,'ec2','describe_network_acls','*','NetworkAcls',None,{},None)
      self.cache_call(False,'ec2','describe_vpcs','*','Vpcs',None,{}, None)
      self.cache_call(True,'ec2','describe_route_tables','*','RouteTables',None,{},None)
      self.cache_call(True,'ec2','describe_subnets','*','Subnets',None, {} ,None)
      self.cache_call(False,'ec2','describe_flow_logs','*','FlowLogs',None,{},None)
      self.cache_call(True,'ec2','describe_iam_instance_profile_associations','*','IamInstanceProfileAssociations',None,{},None)
      self.cache_call(True,'ec2','describe_internet_gateways','*','InternetGateways',None,{},None)
      self.cache_call(True,'ec2','describe_nat_gateways','*','NatGateways',None,{},None)
      self.cache_call(True,'ec2','describe_snapshots','*','Snapshots',None,{ 'OwnerIds' : [ 'self' ] },None)
      self.cache_call(True,'ec2','describe_vpc_peering_connections','*','VpcPeeringConnections',None,{},None)

      # == ELB
      self.cache_call(True,'elb','describe_load_balancers','*','LoadBalancerDescriptions',None,{},None)
      
      # == ELBv2
      e = self.cache_call(False,'elbv2','describe_load_balancers','*','LoadBalancers',None,{},None)
      for region in e:
         for elb in e[region]:
            self.cache_call(True,'elbv2','describe_listeners',region,'Listeners',None,{ 'LoadBalancerArn' : elb['LoadBalancerArn'] },None)
            self.cache_call(True,'elbv2','describe_target_groups',region,'TargetGroups',None,{ 'LoadBalancerArn' : elb['LoadBalancerArn'] },None)
      
      # == EKS
      self.cache_call(True,'eks','list_clusters','*','clusters',None,{},None)
      
      # == GuardDuty
      self.cache_call(True,'guardduty','list_detectors','*','DetectorIds',None,{},None)
      
      # == IAM
      self.cache_call(False,'iam','get_account_summary',None,'SummaryMap',None, {}, None)
      self.cache_call(False,'iam','get_account_authorization_details',None,'UserDetailList',None,{},None)
      if not 'AccountPasswordPolicy' in self.cache['iam']:
         self.cache['iam']['AccountPasswordPolicy'] = self.iam_AccountPasswordPolicy()
         self.write_json()
      
      # == IAM Groups
      for g in self.cache_call(False,'iam','list_groups',None,'Groups',None):
         self.cache_call(False,'iam','get_group',None,None,None,{'GroupName' : g['GroupName'] },g['GroupName'])
         self.cache_call(True,'iam','list_attached_group_policies',None,'AttachedPolicies',None,{'GroupName' : g['GroupName']},g['GroupName'])
         for PolicyName in self.cache_call(True,'iam','list_group_policies',None,'PolicyNames',None,{'GroupName' : g['GroupName'] },g['GroupName']):
            self.cache_call(False,'iam','get_group_policy',None,'PolicyDocument', None,{'GroupName' : g['GroupName'],'PolicyName' : PolicyName } , g['GroupName'] + ':' + PolicyName)
            
      # == IAM Policies
      for p in self.cache_call(True,'iam','list_policies',None,'Policies',None):
         self.cache_call(False,'iam','get_policy_version',None,'PolicyVersion',None,{ 'PolicyArn' : p['Arn'] , 'VersionId' : p['DefaultVersionId'] } ,p['PolicyName'])
      
      # == IAM Users
      for u in self.cache_call(False,'iam','list_users',None,'Users'):
         self.cache_call(True,'iam','list_attached_user_policies',None,'AttachedPolicies',None,{'UserName' : u['UserName'] } ,u['UserName'])
         for PolicyName in self.cache_call(True,'iam','list_user_policies',None,'PolicyNames',None,{'UserName' : u['UserName'] },u['UserName']):
            self.cache_call(False,'iam','get_user_policy',None,'PolicyDocument', None,{'UserName' : u['UserName'],'PolicyName' : PolicyName } , u['UserName'] + ':' + PolicyName)

      if not 'get_credential_report' in self.cache['iam']:
         self.cache['iam']['get_credential_report'] = self.iam_get_credential_report()
         self.write_json()
         
      # == IAM Roles
      for r in self.cache_call(False,'iam','list_roles',None,'Roles'):
         self.cache_call(True,'iam','list_attached_role_policies',None,'AttachedPolicies',None,{'RoleName' : r['RoleName']}, r['RoleName'])
         for PolicyName in self.cache_call(True,'iam','list_role_policies',None,'PolicyNames',None,{'RoleName' : r['RoleName'] },r['RoleName']):
            self.cache_call(False,'iam','get_role_policy',None,'PolicyDocument', None,{'RoleName' : r['RoleName'],'PolicyName' : PolicyName } , r['RoleName'] + ':' + PolicyName)
      
      # == KMS
      k = self.cache_call(False,'kms','list_keys','*','Keys')
      for region in k:
         for key in k[region]:
            self.cache_call(False,'kms','get_key_rotation_status',region,'KeyRotationEnabled',None, {'KeyId' : key['KeyId'] } , key['KeyId'])
      
      # == Lambda
      self.cache_call(True,'lambda','list_functions','*','Functions')
      
      # == Logs
      self.cache_call(True,'logs','describe_metric_filters','*','metricFilters',None,{},None)
      
      # == Organizations
      self.cache_call(False,'organizations','describe_organization',None,'Organization',None, {},None)
      # -- only run this if you are the master account
      if self.cache['sts']['get_caller_identity']['Account'] == self.cache['organizations']['describe_organization']['MasterAccountId']:
         self.cache_call(False,'organizations','list_accounts',None,'Accounts',None, {},None)
     
      # == RDS
      self.cache_call(False,'rds','describe_db_instances','*','DBInstances',None,{},None)
      
      # == Route 53
      self.cache_call(True,'route53','list_hosted_zones',None,'HostedZones',None,{},None)
      
      # == S3
      for s in self.cache_call(False,'s3','list_buckets',None,'Buckets',None, {} , None):
         self.cache_call(False,'s3','get_bucket_policy',None,'Policy',None,{'Bucket' : s['Name']},s['Name'])
         self.cache_call(False,'s3','get_bucket_encryption',None,'ServerSideEncryptionConfiguration',None,{'Bucket' : s['Name']},s['Name'])
         self.cache_call(False,'s3','get_bucket_acl',None,None,None,{'Bucket' : s['Name']},s['Name'])

         if not '_public_s3_bucket' in self.cache['s3']:
            self.cache['s3']['_public_s3_bucket'] = {}
         if not s['Name'] in self.cache['s3']['_public_s3_bucket']:
            self.cache['s3']['_public_s3_bucket'][s['Name']] = self.check_if_S3_bucket_is_public(s['Name'])
      
      # -- check the CloudTrail S3 buckets
      for region in self.cache['cloudtrail']['describe_trails']:
         for ct in self.cache['cloudtrail']['describe_trails'][region]:
            if 'S3BucketName' in ct:
               if not ct['S3BucketName'] in self.cache['s3']['_public_s3_bucket']:
                  self.cache['s3']['_public_s3_bucket'][ct['S3BucketName']] = self.check_if_S3_bucket_is_public(ct['S3BucketName'])
                     
      # == SNS
      self.cache_call(True,'sns','list_topics','*','Topics',None,{},None)
      
      # == SSM
      self.cache_call(True,'ssm','describe_instance_information','*','InstanceInformationList',None,{}, None)
      self.cache_call(True,'ssm','get_parameters_by_path','*','Parameters',None,{'Path' : '/', 'Recursive' : True})
      
      # == WAF
      x = self.cache_call(False,'waf','list_web_acls',None,'WebACLs',None,{}, None)
      for w in x:
         self.cache_call(False,'waf','get_web_acl',region,'WebACL',None,{ 'WebACLId' : w['WebACLId']}, None)
         
      x = self.cache_call(False,'waf','list_rules',None,'Rules',None,{}, None)
      for w in x:
         self.cache_call(False,'waf','get_rule',None,'Rule',None,{'RuleId' : w['RuleId'] }, None)
         
      x = self.cache_call(False,'waf-regional','list_web_acls','*','WebACLs',None,{}, None)
      for region in x:
         for w in x[region]:
            self.cache_call(False,'waf-regional','get_web_acl',region,'WebACL',None,{ 'WebACLId' : w['WebACLId']}, None)
            
      x = self.cache_call(False,'waf-regional','list_rules','*','Rules',None,{}, None)
      for region in x:
         for w in x[region]:
            self.cache_call(False,'waf-regional','get_rule',region,'Rule',None,{'RuleId' : w['RuleId'] }, None)
            
      
      # == WAFv2
      self.cache_call(False,'wafv2','list_web_acls','*','WebACLs',None,{'Scope' : 'REGIONAL' }, None)
      self.cache_call(False,'wafv2','list_web_acls',None,'WebACLs',None,{'Scope' : 'CLOUDFRONT' }, 'CLOUDFRONT')
      
      
      
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
   c.cache_call(False,'sts','get_caller_identity')       # We do this one first, so we know what account we're talking about
   
   c.data_file = file
   c.read_json(file)
   
   c.collect_all()
   
if __name__ == '__main__':
   main()