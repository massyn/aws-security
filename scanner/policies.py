import json
import time
import datetime as dt
import dateutil
import jmespath
import os

class policies:
   
   def __init__(self,p):
      self.cache = p
      self.findings = {}

   def convert_timestamp(self,item_date_object):
      if isinstance(item_date_object, (dt.date,dt.datetime)):
         return item_date_object.timestamp()

   def security_groups(self,t,region):
      # process the security groups into something a bit more managable
      flat = []
      grp = {}
      
      for SS in self.cache['ec2']['describe_security_groups'].get(region,{}):
         for sg in SS['SecurityGroups']:
            grp['GroupId'] = sg['GroupId']
            grp['GroupName'] = sg['GroupName']
            
            for r in sg[t]:
                  grp['FromPort'] = r.get('FromPort',0)
                  grp['ToPort'] = r.get('ToPort',65535)
                  grp['IpProtocol'] = r['IpProtocol']
                  for i in r['IpRanges']:
                     grp['IpRange'] = i['CidrIp']
                     cp = {}
                     for g in grp:
                        cp[g] = grp[g]
                     
                     flat.append(cp)

                  for i in r['Ipv6Ranges']:
                     grp['IpRange'] = i['CidrIpv6']

                     cp = {}
                     for g in grp:
                        cp[g] = grp[g]
                     
                     flat.append(cp)
      return flat

   def flatten(self,client,function,key = None):
      '''
      Use case 1 - lambda / list_functions / region /  Functions

      Use case 2 - ec2 / describe_instances / region / ['Reservations' , 'Instances' ]

      Use case 3 - iam / get_credential_report / region

      '''
      result = []
      for region in self.cache[client][function]:
         for data in self.cache[client][function].get(region,{}):
            if key == None:
               result.append(data)
            else:
               if type(key) == list:
                  for d in data[key[0]]:
                     if key[1] in d:
                        for e in d[key[1]]:
                           e['_region'] = region
                           result.append(e)
               else:
                  for d in data[key]:
                     d['_region'] = region
                     result.append(d)
      return result

   def processor(self):
      '''
         Change the collected data into a more flattened structure that is better suited for jmespath
      '''
      result = {}
      parameters = [
         #  client     function                       key to filter on             item indexed
         [ 'lambda' ,'list_functions'                ,'Functions'                  ,False ],
         [ 'ec2'    ,'describe_instances'            ,['Reservations','Instances'] ,False ],
         [ 'ec2'    ,'describe_subnets'              ,'Subnets'                    ,False ],
         [ 'iam'    ,'get_credential_report'         ,None                         ,False ],
         [ 'iam'    ,'list_virtual_mfa_devices'      ,'VirtualMFADevices'          ,False ],
         [ 'iam'    ,'list_user_policies'            ,'PolicyNames'                ,True  ],
         [ 'iam'    ,'list_attached_user_policies'   ,'AttachedPolicies'           ,True  ],
         [ 'ssm'    ,'describe_instance_information' ,'InstanceInformationList'    ,False ]
         
      ]
      for (client,function,key,item) in parameters:
         if not client in result:
            result[client] = {}
         if item == False:
            result[client][function] = self.flatten(client,function,key)
         else:
            if function not in result[client]:
               result[client][function] = {}

            for region in self.cache[client].get(function,{}):
               for itemKey in self.cache[client][function].get(region,{}):
                  if not itemKey in result[client][function]:
                     result[client][function][itemKey] = []
                  for x in self.cache[client][function].get(region,{})[itemKey]:
                     for y in x[key]:
                        result[client][function][itemKey].append(y)

      # == merging
      parameters = [
         [ 'iam'     ,  'get_credential_report' , 'arn' ,               'iam','list_virtual_mfa_devices','[?User.Arn==\'%KEY%\']']
      ]
      for (client,function,key,joined_client,joined_function,onKey) in parameters:
         new = []
         for blob in result[client][function]:
            theKey = jmespath.search(key,blob)
            myKey = onKey.replace('%KEY%',theKey)
            r = jmespath.search(myKey,result[joined_client][joined_function])
            if len(r) >= 1:
               blob[joined_function] = r[0]
            else:
               blob[joined_function] = {}

            new.append(blob)
         result[client][function] = new

      # == merge user accounts
      new = []
      for blob in result['iam']['get_credential_report']:
         blob['list_user_policies'] = result['iam']['list_user_policies'].get(blob['user'],{})
         blob['_list_user_policies_count'] = len(blob['list_user_policies'])
         blob['list_attached_user_policies'] = result['iam']['list_attached_user_policies'].get(blob['user'],{})
         blob['_list_attached_user_policies_count'] = len(blob['list_attached_user_policies'])
         new.append(blob)

      result['iam']['get_credential_report'] = new

      #print(json.dumps(result,indent=4))
      return result

   def execute(self):
      print('*** POLICIES ***')

      # -- process our policies from the json file
      processed_data = self.processor()

      with open (__file__ + '.json','rt') as f:
         pj = json.load(f)

         for pl in pj:
            pl['name'] = pl.get('references',['NO REFERENCE'])[0] + ' - ' + pl['name']
            source = jmespath.search(pl['source'],processed_data)
            broken = jmespath.search(pl['filter'],source)
            for b in broken:
               self.finding(pl,0,b)

            for a in range(0,len(source)-len(broken)):
               self.finding(pl,1,None)
            
            # == this DEBUG code only exists to help troubleshoot new policy rules
            if 'DEBUG' in pl['name']:
               print('********** SOURCE ************')
               print(json.dumps(source,indent=4))
               
               print('********** BROKEN ************')
               print(json.dumps(broken,indent=4))

      # == continue with the legacy policies

      p = self.cache
      regionList = [x['RegionName'] for x in self.cache['ec2']['describe_regions'].get('us-east-1',{})['Regions']]
      accountId = self.cache.get('sts',{}).get('get_caller_identity',{}).get('us-east-1',{})['Account']
      
      # ------------------------------------------------------
      policy = {
         'name'  : 'Ensure SSM is enabled on all EC2 instances',
         'description' : 'AWS Systems Manager allows for the management of EC2 instances, allowing you to scale operations like patching across the entire EC2 fleet.',
         'vulnerability' : 'By not having SSM, operational teams will spend manual effort to patch and manage the environment.',
         'severity' : 'low',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete">AWS Best practices</a> to enable MFA delete.',
         'references' : [
               ''
         ],
         'links' : [
            'https://docs.aws.amazon.com/systems-manager/latest/userguide/what-is-systems-manager.html'
         ]
      }
      ssm_i = []
      for i in processed_data['ssm']['describe_instance_information']:
         ssm_i.append(i['InstanceId'])

      for i in processed_data['ec2']['describe_instances']:
         if i['State']['Name'] == 'running':
            # -- find the name
            Name = ''
            for t in i.get('Tags',{}):
               if t['Key'] == 'Name':
                  Name = t['Value']

            # -- build the evidence blob
            evidence = {
               'InstanceId'         : i['InstanceId'],
               'Region'             : i['_region'],
               'PrivateIpAddress'   : i['PrivateIpAddress'],
               'Name'               : Name
            }
            
            self.finding(policy,i['InstanceId'] in ssm_i,evidence)
      
      # ------------------------------------------------------
      policy = {
         'name'  : 'Ensure MFA Delete is enable on S3 buckets',
         'description' : 'Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication.',
         'vulnerability' : 'Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.',
         'severity' : 'low',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete">AWS Best practices</a> to enable MFA delete.',
         'references' : [
               'AWS CIS v.1.4.0 - 2.1.3'
         ],
         'links' : [
            'https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete',
            'https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMFADelete.html',
            'https://aws.amazon.com/blogs/security/securing-access-to-aws-using-mfa-part-3/',
            'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_lost-or-broken.html'
         ]
      }
      
      for s3 in p['s3']['list_buckets'].get('us-east-1',{})['Buckets']:
         self.finding(policy,p['s3']['get_bucket_versioning'].get('us-east-1',{}).get(s3['Name']).get('MFADelete') == 'Enabled',s3['Name'])

      # ------------------------------------------------------
      policy = {
         'name'  : 'Ensure all S3 buckets employ encryption-at-rest',
         'description' : 'Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.',
         'vulnerability' : 'Amazon S3 buckets with default bucket encryption using SSE-KMS cannot be used as destination buckets for Amazon S3 server access logging. Only SSE-S3 default encryption is supported for server access log destination buckets.',
         'severity' : 'medium',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonS3/latest/user-guide/default-bucket-encryption.html">AWS Best practices</a>.',
         'references' : [
               'AWS CIS v.1.4.0 - 2.1.1'
         ],
         'links' : [
            'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/default-bucket-encryption.html',
            'https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html#bucket-encryption-related-resources'
         ]
      }
      
      for s3 in p['s3']['list_buckets'].get('us-east-1',{})['Buckets']:
         compliance = False
         for rule in p['s3']['get_bucket_encryption']['us-east-1'][s3['Name']].get('ServerSideEncryptionConfiguration',{}).get('Rules',[]):
            if rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'AES256' or 'aws:kms' in rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']:
               compliance = 1
         self.finding(policy,compliance,s3['Name'])

      # ------------------------------------------------------
      policy = {
         'name'  : 'Ensure that S3 Buckets are configured with Block public access (bucket settings)',
         'description' : 'Amazon S3 provides Block public access (bucket settings) and Block public access (account settings) to help you manage public access to Amazon S3 resources. By default, S3 buckets and objects are created with public access disabled. However, an IAM principal with sufficient S3 permissions can enable public access at the bucket and/or object level. While enabled, Block public access (bucket settings) prevents an individual bucket, and its contained objects, from becoming publicly accessible. Similarly, Block public access (account settings) prevents all buckets, and contained objects, from becoming publicly accessible across the entire account.',
         'vulnerability' : 'Amazon S3 Block public access (bucket settings) prevents the accidental or malicious public exposure of data contained within the respective bucket(s). Amazon S3 Block public access (account settings) prevents the accidental or malicious public exposure of data contained within all buckets of the respective AWS account. Whether blocking public access to all or some buckets is an organizational decision that should be based on data sensitivity, least privilege, and use case.',
         'severity' : 'medium',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete">AWS Best practices</a> to enable MFA delete.',
         'references' : [
               'AWS CIS v.1.4.0 - 2.1.5'
         ],
         'links' : [
            'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/block-public-access-account.html'
         ]
      }
      
      for s3 in p['s3']['list_buckets'].get('us-east-1',{})['Buckets']:
         x = p['s3']['get_public_access_block'].get('us-east-1',{}).get(s3['Name']).get('PublicAccessBlockConfiguration',{})
         ok = 0
         for param in ['BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets']:
            if x.get(param):
               ok += 1
         self.finding(policy,ok == 4,{ s3['Name'] : x })

      # ------------------------------------------------------
      policy = {
         'name'  : 'Ensure EBS volume encryption is enabled',
         'description' : 'Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported.',
         'vulnerability' : 'Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.',
         'severity' : 'medium',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html">AWS Best practices</a>.',
         'references' : [
               'AWS CIS v.1.4.0 - 2.2.1'
         ],
         'links' : [
            'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
            'https://aws.amazon.com/blogs/aws/new-opt-in-to-default-encryption-for-new-ebs-volumes/'
         ]
      }
      for region in regionList:
         x = p['ec2']['get_ebs_encryption_by_default'].get(region,{})
         self.finding(policy,x.get('EbsEncryptionByDefault',False),region)

      # ------------------------------------------------------
      policy = {
         'name'  : 'Ensure that Object-level logging for write events is enabled for S3 bucket',
         'description' : 'S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don\'t log data events and so it is recommended to enable Object-level logging for S3 buckets.',
         'vulnerability' : 'Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity within your S3 Buckets using Amazon CloudWatch Events.',
         'severity' : 'low',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-cloudtrail-events.html">AWS Best practices</a>.',
         'references' : [
               'AWS CIS v.1.4.0 - 3.10'
         ],
         'links' : [
            'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-cloudtrail-events.html'
         ]
      }

      s3List = {}
      for s3 in p['s3']['list_buckets'].get('us-east-1',{})['Buckets']:
         s3List['arn:aws:s3:::' + s3['Name'] + '/'] = 0

      for region in regionList:
         for c in p['cloudtrail']['list_trails'].get(region,{}):
            for t in c['Trails']:
               for e in p['cloudtrail']['get_event_selectors'].get(region,{})[t['TrailARN']]['EventSelectors']:
                  if e['ReadWriteType'] in ['All','WriteOnly']:
                     for x in e['DataResources']:
                        if x['Type'] == 'AWS::S3::Object':
                           for y in x['Values']:
                              if y == 'arn:aws:s3':
                                 for s in s3List:
                                    s3List[s] = 1
                              else:
                                 s3List[y] = 1
      for s in s3List:
         self.finding(policy,s3List[s],s)

      # ------------------------------------------------------
      policy = {
         'name'  : 'Ensure that Object-level logging for read events is enabled for S3 bucket',
         'description' : 'S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don\'t log data events and so it is recommended to enable Object-level logging for S3 buckets.',
         'vulnerability' : 'Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity using Amazon CloudWatch Events.',
         'severity' : 'low',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-cloudtrail-events.html">AWS Best practices</a>.',
         'references' : [
               'AWS CIS v.1.4.0 - 3.11'
         ],
         'links' : [
            'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-cloudtrail-events.html'
         ]
      }

      s3List = {}
      for s3 in p['s3']['list_buckets'].get('us-east-1',{})['Buckets']:
         s3List['arn:aws:s3:::' + s3['Name'] + '/'] = 0

      for region in regionList:
         for c in p['cloudtrail']['list_trails'].get(region,{}):
            for t in c['Trails']:
               for e in p['cloudtrail']['get_event_selectors'].get(region,{})[t['TrailARN']]['EventSelectors']:
                  if e['ReadWriteType'] in ['All','ReadOnly']:
                     for x in e['DataResources']:
                        if x['Type'] == 'AWS::S3::Object':
                           for y in x['Values']:
                              if y == 'arn:aws:s3':
                                 for s in s3List:
                                    s3List[s] = 1
                              else:
                                 s3List[y] = 1
      for s in s3List:
         self.finding(policy,s3List[s],s)

      # ------------------------------------------------------
      policy = {
         'name'  : 'Ensure that IAM Access analyzer is enabled for all regions',
         'description' : 'IAM Access Analyzer is a technology introduced at AWS reinvent 2019. After the Analyzer is enabled in IAM, scan results are displayed on the console showing the accessible resources. Scans show resources that other accounts and federated users can access, such as KMS keys and IAM roles. So the results allow you to determine if an unintended user is allowed, making it easier for administrators to monitor least privileges access. Access Analyzer analyzes only policies that are applied to resources in the same AWS Region.',
         'vulnerability' : 'AWS IAM Access Analyzer helps you identify the resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, that are shared with an external entity. This lets you identify unintended access to your resources and data. Access Analyzer identifies resources that are shared with external principals by using logic-based reasoning to analyze the resource-based policies in your AWS environment. IAM Access Analyzer continuously monitors all policies for S3 bucket, IAM roles, KMS(Key Management Service) keys, AWS Lambda functions, and Amazon SQS(Simple Queue Service) queues.',
         'severity' : 'medium',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html">AWS Best practices</a> to enable access analyzer.',
         'references' : [
               'AWS CIS v.1.4.0 - 1.20'
         ],
         'links' : [
            'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html',
            'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html',
            'https://docs.aws.amazon.com/cli/latest/reference/accessanalyzer/get-analyzer.html',
            'https://docs.aws.amazon.com/cli/latest/reference/accessanalyzer/create-analyzer.html'
         ]
      }
      for region in regionList:
         status = 'UNKNOWN'
         for AA in p['accessanalyzer']['list_analyzers'].get(region,{}):
            for a in AA['analyzers']:
               status = a['status']
         self.finding(policy,status == 'ACTIVE', region)

      # ------------------------------------------------------
      policy = {
         'name'  : 'Ensure that encryption is enabled for RDS Instances',
         'description' : 'Amazon RDS encrypted DB instances use the industry standard AES-256 encryption algorithm to encrypt your data on the server that hosts your Amazon RDS DB instances. After your data is encrypted, Amazon RDS handles authentication of access and decryption of your data transparently with a minimal impact on performance.',
         'vulnerability' : 'Databases are likely to hold sensitive and critical data, it is highly recommended to implement encryption in order to protect your data from unauthorized access or disclosure. With RDS encryption enabled, the data stored on the instance\'s underlying storage, the automated backups, read replicas, and snapshots, are all encrypted.',
         'severity' : 'medium',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html">AWS Best practices</a> to enable database encryption.',
         'references' : [
               'AWS CIS v.1.4.0 - 2.3.1'
         ],
         'links' : [
            'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
            'https://aws.amazon.com/blogs/database/selecting-the-right-encryption-options-for-amazon-rds-and-amazon-aurora-database-engines/',
            'https://aws.amazon.com/rds/features/security/'

         ]
      }
      for region in regionList:
         for r in p['rds']['describe_db_instances'].get(region,{}):
            for i in r['DBInstances']:
               self.finding(policy,i['StorageEncrypted'],{ 'DBInstanceIdentifier' : i['DBInstanceIdentifier'], 'DbiResourceId' : i['DbiResourceId'] })
      
      # ------------------------------------------------------
      policy = {
         'name' : 'Ensure IAM password policy requires minimum length of 14 or greater',
         'description' : 'IAM Password Policy specifies the password complexity requirements for the AWS IAM users.',
         'vulnerability' : 'Weak password policies will cause users to select weak, easy to guess passwords.',
         'severity' : 'medium',
         'remediation' : '''Follow the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html">AWS Best Practices</a> to set an IAM Password Policy.<ul>
         
         ''',
         'references' : [
               'AWS CIS v.1.4.0 - 1.8',
               'AWS CIS v.1.2.0 - 1.9',
         ],
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=20',
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html'
         ]
      }
      if p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('minimum_password_length') == None:
         self.finding(policy,0,{ 'minimum_password_length' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('minimum_password_length') })
      else:
         if p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('minimum_password_length') >= 14:
               self.finding(policy,1,{ 'minimum_password_length' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('minimum_password_length') })
         else:
               self.finding(policy,0,{ 'minimum_password_length' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('minimum_password_length') })
      
      # ------------------------------------------------------
      policy = {
         'name' : 'Ensure IAM password policy prevents password reuse',
         'description' : 'IAM Password Policy specifies the password complexity requirements for the AWS IAM users.',
         'vulnerability' : 'Weak password policies will cause users to select weak, easy to guess passwords.',
         'severity' : 'medium',
         'remediation' : '''Follow the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html">AWS Best Practices</a> to set an IAM Password Policy.<ul>
         
         ''',
         'references' : [
               'AWS CIS v.1.4.0 - 1.9',
               'AWS CIS v.1.2.0 - 1.10',
         ],
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=20',
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html'
         ]
      }
      if p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('password_reuse_prevention') == None:
         self.finding(policy,0,{ 'password_reuse_prevention' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('password_reuse_prevention') })
      else:
         if p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('password_reuse_prevention') >= 24:
               self.finding(policy,1,{ 'password_reuse_prevention' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('password_reuse_prevention') })
         else:
               self.finding(policy,0,{ 'password_reuse_prevention' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('password_reuse_prevention') })
      
      # ------------------------------------------------------
      policy = {
         'name' : 'Ensure IAM password policy is set to a strong password',
         'description' : 'IAM Password Policy specifies the password complexity requirements for the AWS IAM users.',
         'vulnerability' : 'Weak password policies will cause users to select weak, easy to guess passwords.',
         'severity' : 'medium',
         'remediation' : '''Follow the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html">AWS Best Practices</a> to set an IAM Password Policy.<ul>
         
         <li>1.5 Ensure IAM password policy requires at least one uppercase letter</li>
         <li>1.6 Ensure IAM password policy require at least one lowercase letter</li>
         <li>1.7 Ensure IAM password policy require at least one symbol</li>
         <li>1.8 Ensure IAM password policy require at least one number</li>
         <li>1.11 Ensure IAM password policy expires passwords within 90 days or less</li>

         </ul>''',
         'references' : [
               'AWS CIS v.1.2.0 - 1.5',
               'AWS CIS v.1.2.0 - 1.6',
               'AWS CIS v.1.2.0 - 1.7',
               'AWS CIS v.1.2.0 - 1.8',
               'AWS CIS v.1.2.0 - 1.11'
         ],
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=20',
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html'
         ]
      }
      
      if p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_uppercase_characters'):
         self.finding(policy,1,{ 'require_uppercase_characters' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_uppercase_characters') })
      else:
         self.finding(policy,0,{ 'require_uppercase_characters' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_uppercase_characters') })

      if p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_lowercase_characters'):
         self.finding(policy,1,{ 'require_lowercase_characters' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_lowercase_characters') })
      else:
         self.finding(policy,0,{ 'require_lowercase_characters' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_lowercase_characters') })

      if p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_symbols'):
         self.finding(policy,1,{ 'require_symbols' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_symbols') })
      else:
         self.finding(policy,0,{ 'require_symbols' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_symbols') })

      if p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_numbers'):
         self.finding(policy,1,{ 'require_numbers' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_numbers') })
      else:
         self.finding(policy,0,{ 'require_numbers' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('require_numbers') })

      if p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('max_password_age') == None:
         self.finding(policy,0,{ 'max_password_age' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('max_password_age') })
      else:
         if p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('max_password_age') <= 90:
               self.finding(policy,1,{ 'max_password_age' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('max_password_age') })
         else:
               self.finding(policy,0,{ 'max_password_age' : p['iam'].get('AccountPasswordPolicy',{}).get('us-east-1',{}).get('max_password_age') })

      # ------------------------------------------------------
      policy = {
         'name' : 'Ensure IAM instance roles are used for AWS resource access from instances',
         'description' : 'AWS IAM roles reduce the risks associated with sharing and rotating credentials that can be used outside of AWS itself. If credentials are compromised, they can be used from outside of the AWS account they give access to. In contrast, in order to leverage role permissions an attacker would need to gain and maintain access to a specific instance to use the privileges associated with it.',
         'vulnerability' : 'AWS access from within AWS instances can be done by either encoding AWS keys into AWS API calls or by assigning the instance to a role which has an appropriate permissions policy for the required access. "AWS Access" means accessing the APIs of AWS in order to access AWS resources or manage AWS account resources.',
         'remediation' : 'Remove the access keys from any user account in use on an EC2 instance, and setup EC2 IAM Roles instead.',
         'severity' : 'low',
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=49',
               'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html'
         ],
         'references' : [
               'AWS CIS v.1.4.0 - 1.18',
               'AWS CIS v.1.2.0 - 1.19'
         ]
      }
      
      for region in regionList:
         for e in self.cache['ec2']['describe_instances'].get(region,{}):
            for R in e['Reservations']:
               for ec2 in R['Instances']:
                  compliance = 0
                  evidence = {region : ec2['InstanceId']}
                  for II in self.cache['ec2']['describe_iam_instance_profile_associations'].get(region,{}):
                     for ia in II['IamInstanceProfileAssociations']:
                        if ia['InstanceId'] == ec2['InstanceId'] and ia['State'] == 'associated':
                           compliance = 1   
                     self.finding(policy,compliance,evidence)
      # ------------------------------------------------------
      policy = {
         'name'  : 'Ensure a support role has been created to manage incidents with AWS Support',
         'description' : 'The AWS Support Role allows a user to create and manage support cases with AWS.',
         'vulnerability' : 'Without a support role, no one (with the exception of the root user) will be able to open a support case with AWS.  Note that there are charges for using the support service from AWS.  Refer to their <a href="https://aws.amazon.com/premiumsupport/pricing/">support pricing model</a> for more information.',
         'remediation' : 'Assign the policy AWSSupportAccess to a user or a group.',
         'severity' : 'info',
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=52',
               'https://aws.amazon.com/premiumsupport/pricing/',
               'https://docs.aws.amazon.com/awssupport/latest/user/getting-started.html',
               'https://docs.aws.amazon.com/awssupport/latest/user/accessing-support.html#iam'
         ],
         'references' : [
               'AWS CIS v.1.4.0 - 1.17',
               'AWS CIS v.1.2.0 - 1.20'
         ]
      }

      # -- cycle through all the users
      compliance = 0
      evidence = []
      if not 'get_credential_report' in p['iam']:
         self.finding(policy,0,'credential report is not available')
      else:
         for u in p['iam']['get_credential_report'].get('us-east-1',{}):
            if u['user'] != '<root_account>':
                  # -- check the user's attached policies
                  for A in self.cache['iam']['list_attached_user_policies'].get('us-east-1',{})[u['user']]:
                     for aup in A['AttachedPolicies']:
                        if aup['PolicyArn'] == 'arn:aws:iam::aws:policy/AWSSupportAccess':
                           evidence.append({'user' : u['user']})
                           compliance = 1

                  # -- check the user's groups
                  for B in self.cache['iam']['get_account_authorization_details'].get('us-east-1',{}): 
                     for aad in B['UserDetailList']:
                        if aad['UserName'] == u['user']:
                           for g in aad['GroupList']:
                                 for C in self.cache['iam']['list_attached_group_policies'].get('us-east-1',{})[g]:
                                    for agp in C['AttachedPolicies']:
                                       if agp['PolicyArn'] == 'arn:aws:iam::aws:policy/AWSSupportAccess':
                                          compliance = 1
                                          evidence.append({ 'user' : u['user'], 'group' : g})

                  # -- check the role
                  for D in self.cache['iam']['get_account_authorization_details'].get('us-east-1',{}):
                     for aad in D['RoleDetailList']:
                        for amp in aad['AttachedManagedPolicies']:
                           if amp['PolicyArn'] == 'arn:aws:iam::aws:policy/AWSSupportAccess':
                                 evidence.append({'role' : aad['RoleName']})

                                 compliance = 1

         self.finding(policy,compliance,evidence)
     
      # ------------------------------------------------------
      policy = {
         'name' : 'Ensure IAM policies that allow full "*:*" administrative privileges are not created',
         'description' : 'Policies define the list of actions that is allowed against a set of resources.  They typically represent all the actions an entity can take as part of a required job function.',
         'vulnerability' : 'Creating an additional policy with administrative access to the entire AWS account has a risk of going undetected, if it is were to be added to a rogue account, leading to a compromise of the AWS account.',
         'remediation' : 'Remove the offending policy, and add the user, group, or role to the AWS managed Administrator policy',
         'severity' : 'medium',
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=57'
         ],
         'references' : [
               'AWS CIS v.1.4.0 - 1.16',
               'AWS CIS v.1.2.0 - 1.22'
         ]
      }
      evidence = {}
      compliance = 1  # in this case we assume everything is fine, until we find something that is not
      for gpv in self.cache['iam']['get_policy_version']:
         if gpv != 'AdministratorAccess':
            if 'Document' in self.cache['iam']['get_policy_version'][gpv]:
               if type(self.cache['iam']['get_policy_version'][gpv]['Document']['Statement']) == dict:
                     s = self.cache['iam']['get_policy_version'][gpv]['Document']['Statement']
                     if self.comparer(s['Effect'],'Allow') and self.comparer(s['Action'],'*') and self.comparer(s['Resource'],'*'):
                           compliance = 0
                           evidence[gpv] = s
               else:
                     for s in self.cache['iam']['get_policy_version'][gpv]['Document']['Statement']:
                        if self.comparer(s['Effect'],'Allow') and self.comparer(s.get('Action',''),'*') and self.comparer(s['Resource'],'*'):
                           compliance = 0
                           evidence[gpv] = s
            else:
               compliance = 0
               evidence[gpv] = 'policy details not available'
               
            self.finding(policy,compliance,evidence)

      # ------------------------------------------------------
      policy = {
         'name' : 'Ensure CloudTrail is enabled in all regions',
         'description' : 'The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing.',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html">AWS Best Practices</a> to create a new trail.',
         'vulnerability' : 'Without proper logging of AWS API activity, any activity, be it malicious, or legitimate will go undetected, resulting in breaches, or lack of regulatory compliance.',
         'severity' : 'medium',
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=61',
               'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html',
               'https://aws.amazon.com/premiumsupport/technology/trusted-advisor/best-practice-checklist/#Security'
         ],
         'references' : [
               'AWS CIS v.1.4.0 - 3.1',
               'AWS CIS v.1.2.0 - 2.1',
               'Trusted Advisor - AWS Cloudtrail logging'
         ]
      }

      IsMultiRegionTrail = False
      IsLogging = False
      IncludeManagementEvents = False
      ReadWriteType = False

      for region in regionList:            
         for ct in self.cache['cloudtrail']['describe_trails'].get(region,{}).get('trailList',{}):
            # IsMultiRegionTrail
            if ct['IsMultiRegionTrail']:
               IsMultiRegionTrail = True

            if self.cache['cloudtrail']['get_trail_status'].get(region,{})[ct['TrailARN']]:
               IsLogging = True

            for e in self.cache['cloudtrail']['get_event_selectors'].get(region,{})[ct['TrailARN']]['EventSelectors']:
               if e['IncludeManagementEvents'] == True:
                  IncludeManagementEvents = True

               if e['ReadWriteType'] == 'All':
                  ReadWriteType = True
         
         evidence = {
               'region' : region,
               'IsMultiRegionTrail' : IsMultiRegionTrail,
               'IsLogging'             : IsLogging,
               'IncludeManagementEvents'   : IncludeManagementEvents,
               'ReadWriteType'             : ReadWriteType
         }
         if IsMultiRegionTrail == True and IsLogging == True and IncludeManagementEvents == True and ReadWriteType == True:
               self.finding(policy,1,evidence)
         else:
               self.finding(policy,0,evidence)

      
      # ------------------------------------------------------
      policy = {
         'name' : 'Ensure CloudTrail log file validation is enabled',
         'description' : 'Enabling log file validation will provide additional integrity checking of CloudTrail logs.',
         'vulnerability' : 'Without log file validation, there is a higher liklihood of regulatory compliance findings related to audit logging.',
         'severity' : 'low',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html">AWS Best Practices</a> to enable log file validation.',
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=64',
               'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html'
         ],
         'references' : [
               'AWS CIS v.1.4.0 - 3.2',
               'AWS CIS v.1.2.0 - 2.2'
         ]
      }

      for region in regionList:
         for ct in self.cache['cloudtrail']['describe_trails'].get(region,{}).get('trailList',{}):
               evidence = {
                  region : ct['Name']
               }
               if ct['LogFileValidationEnabled']:
                  self.finding(policy,1,evidence)
               else:
                  self.finding(policy,0,evidence)

      # --------------------------------------------------------
      policy = {
         'name' : 'Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible',
         'description' : 'CloudTrail logs a record of every API call made in your AWS account. These logs file are stored in an S3 bucket. It is recommended that the bucket policy,or access control list (ACL),applied to the S3 bucket that CloudTrail logs to prevents public access to the CloudTrail logs.',
         'vulnerability' : 'Allowing public access to CloudTrail log content may aid an adversary in identifying weaknesses in the affected account\'s use or configuration.',
         'severity' : 'critical',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html">AWS Best practices</a> to configure CloudTrail S3 buckets.',
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=66',
               'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html'
         ],
         'references' : [
               'AWS CIS v.1.4.0 - 3.3',
               'AWS CIS v 1.2.0 - 2.3'
         ]
      }
      

      for region in regionList:
         for ct in self.cache['cloudtrail']['describe_trails'].get(region,{}):

            evidence = { 'region' : region }
            if not 'S3BucketName' in ct:
               compliance = True
               evidence['S3BucketName'] = '** No bucket defined ** '
            else:
               S3BucketName = ct.get('S3BucketName')
               evidence['S3BucketName'] = S3BucketName
               evidence['Is_Bucket_Public'] = self.cache['s3']['_public_s3_bucket'][S3BucketName]['list_objects'] 
            
               if self.cache['s3']['_public_s3_bucket'][S3BucketName]['list_objects'] == False and self.cache['s3']['_public_s3_bucket'][S3BucketName]['list_objects_v2'] == False:
                  compliance = True
            
            self.finding(policy,compliance,evidence)

      # --------------------------------------------------------

      policy = {
         'name' : 'Ensure CloudTrail trails are integrated with CloudWatch Logs',
         'description' : 'Sending CloudTrail logs to CloudWatch Logs will facilitate real-time and historic activity logging based on user, API, resource, and IP address, and provides opportunity to establish alarms and notifications for anomalous or sensitivity account activity.',
         'vulnerability' : 'Without sending CloudTrail logs to CloudWatch, real-time alerts will not be visible, and may go undetected',
         'severity' : 'low',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html">AWS Best practices</a> to configure CloudTrail to CloudWatch integration.',
         'reference' : [
               'AWS CIS v.1.4.0 - 3.4',
               'AWS CIS v.1.2.0 - 2.4'
         ],
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=69',
               'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html'
         ]
      }
      for region in regionList:
         evidence = {region: 'none detected'}
         compliance = 0
         for ct in self.cache['cloudtrail']['describe_trails'].get(region,{}).get('trailList',{}):
            if 'LatestCloudWatchLogsDeliveryTime' in self.cache['cloudtrail']['get_trail_status'].get(region,{})[ct['TrailARN']]:
               if isinstance(self.cache['cloudtrail']['get_trail_status'].get(region,{})[ct['TrailARN']]['LatestCloudWatchLogsDeliveryTime'], (dt.date,dt.datetime)):
                  x = self.cache['cloudtrail']['get_trail_status'].get(region,{})[ct['TrailARN']]['LatestCloudWatchLogsDeliveryTime'].timestamp()
               else:
                  x = self.cache['cloudtrail']['get_trail_status'].get(region,{})[ct['TrailARN']]['LatestCloudWatchLogsDeliveryTime']

               if (time.time() - x) < 86400:
                  evidence = {region : self.cache['cloudtrail']['get_trail_status'].get(region,{})[ct['TrailARN']]['LatestCloudWatchLogsDeliveryTime']}
                  compliance = 1
            
         self.finding(policy,compliance,evidence)

      # --------------------------------------------------------
      policy = {
         'name' : 'Ensure AWS Config is enabled in all regions',
         'description' : 'The AWS configuration item history captured by AWS Config enables security analysis, resource change tracking, and compliance auditing.',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html">AWS Best Practices</a> to enable AWS Config in all regions.',
         'vulnerability' : 'Without AWS Config enabled, technical teams will struggle to identify the historical changes to resources when the need arise for forensic investigation.',
         'severity' : 'low',
         'reference' : [
               'AWS CIS v.1.4.0 - 3.5',
               'AWS CIS v.1.2.0 - 2.5'
         ],
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=72',
               'https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html'
         ]
      }
      for region in regionList:
         compliance = 0
         evidence = {'region' : region}
         for c in self.cache['config']['describe_configuration_recorders'].get(region,{}).get('ConfigurationRecorders',{}):
               if c.get('recordingGroup').get('allSupported') == True and c.get('recordingGroup').get('includeGlobalResourceTypes') == True:
                  # == so far so good.  Let's see if we can find the recording status
                  for s in self.cache['config']['describe_configuration_recorder_status'].get(region,{})['ConfigurationRecordersStatus']:
                     if s['name'] == c['name']:
                           if s['recording'] == True and s['lastStatus'] == 'SUCCESS':
                              compliance = 1
         self.finding(policy,compliance,evidence)

      # -------------------------------------------------------
      policy = {
         'name' : 'Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket',
         'description' : 'S3 Bucket Access Logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket.',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html">AWS Best Practices</a> to enable S3 access logging.',
         'vulnerability' : 'By enabling S3 bucket logging on target S3 buckets, it is possible to capture all events which may affect objects within an target buckets. Configuring logs to be placed in a separate bucket allows access to log information which can be useful in security and incident response workflows.',
         'severity' : 'low',
         'reference' : [
               'AWS CIS v.1.4.0 - 3.6',
               'AWS CIS v.1.2.0 - 2.6'
         ],
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=75',
               'https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html'
         ]
      }

      for region in self.cache['cloudtrail']['describe_trails']:
         compliance = 0
         for ct in self.cache['cloudtrail']['describe_trails'].get(region,{}).get('trailList',{}):
            if 'S3BucketName' in ct:
               logging = self.cache['s3']['get_bucket_logging'].get('us-east-1',{}).get(ct['S3BucketName'],{}).get('LoggingEnabled',{}).get('TargetBucket',None)
               if logging != None:
                  compliance = 1
         self.finding(policy,compliance,region)
      # -------------------------------------------------------
      policy = {
         'name' : 'Ensure CloudTrail logs are encrypted at rest using KMS CMKs',
         'description' : 'AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer created master keys (CMK) to further protect CloudTrail logs. It is recommended that CloudTrail be configured to use SSE-KMS.',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html">AWS Best Practices</a> to enable S3 encryption.',
         'vulnerability' : 'Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log data as a given user must have S3 read permission on the corresponding log bucket and must be granted decrypt permission by the CMK policy.',
         'severity' : 'low',
         'reference' : [
               'AWS CIS v.1.4.0 - 3.7',
               'AWS CIS v.1.2.0 - 2.7'
         ],
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=78',
               'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html'
         ]
      }

      for region in self.cache['cloudtrail']['describe_trails']:
         compliance = 0
         for ct in self.cache['cloudtrail']['describe_trails'].get(region,{}).get('trailList',{}):
            if 'KmsKeyId' in ct:
               compliance = 1
         self.finding(policy,compliance,region)

      # -------------------------------------------------------
      policy = {
         'name' : 'Ensure rotation for customer created CMKs is enabled',
         'references' : [
               'AWS CIS v.1.4.0 - 3.8',
               'AWS CIS v.1.2.0 - 2.8'
         ],
         'description' : 'Rotating encryption keys helps reduce the potential impact of a compromised key as data encrypted with a new key cannot be accessed with a previous key that may have been exposed.',
         'vulnerability' : 'By not rotating encryption keys, there is a higher likelihood of data compromize due to improper management of secret keys.',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html">AWS Best Practices</a> to rotate keys.',
         'severity' : 'medium',
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=82',
               'https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html'
         ]
      }
      for region in regionList:
         if region in self.cache['kms']['get_key_rotation_status']:
            for k in self.cache['kms']['get_key_rotation_status'].get(region,{}):
               evidence = { region : k}

               if self.cache['kms']['get_key_rotation_status'].get(region,{})[k] == True:
                  self.finding(policy,1,evidence)
               else:
                  self.finding(policy,0,evidence)

      # -------------------------------------------------------
      policy = {
         'name' : 'Ensure VPC flow logging is enabled in all VPCs',
         'description' : 'VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows.',
         'vulnerability' : 'Without VPC Flow Logs, technical teams will not have visibility on how network traffic flows.',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html">AWS Best Practices</a> to enable VPC Flow Logs.',
         'severity' : 'low',
         'reference' : [
               'AWS CIS v.1.4.0 - 3.9',
               'AWS CIS v.1.2.0 - 2.9'
         ],
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=84',
               'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'
         ]
      }

      for region in regionList:
         for VV in self.cache['ec2']['describe_vpcs'].get(region,{}):
            for v in VV['Vpcs']:
               compliance = 0
               evidence = { region : v['VpcId'] }
               for F in self.cache['ec2']['describe_flow_logs'].get(region,{}):
                  for fl in F['FlowLogs']:
                     if fl['ResourceId'] == v['VpcId']:
                        compliance = 1
                  self.finding(policy,compliance,evidence)

      # --------------------------------------
      # == CIS 3.x is special -- all the metrics are identical, except for the filter pattern.  So we break our "one policy" rule, and combine them all into a list
      POLICIES = [
         {
               'name' : 'Ensure a log metric filter and alarm exist for unauthorized API calls',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for unauthorized API calls.',
               'vulnerability' : 'Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=88'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.1',
                  'AWS CIS v.1.2.0 - 3.1'
               ],
               'filterPattern' : '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for Management Console sign-in without MFA',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for console logins that are not protected by multi-factor authentication (MFA).',
               'vulnerability' : 'Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=92'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.2',
                  'AWS CIS v.1.2.0 - 3.2'
               ],
               'filterPattern' : '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for usage of "root" account',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for root login attempts.',
               'vulnerability' : 'Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=96'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.3',
                  'AWS CIS v.1.2.0 - 3.3'
               ],
               'filterPattern' : '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for IAM policy changes',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established changes made to Identity and Access Management (IAM) policies.',
               'vulnerability' : 'Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=100'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.4',
                  'AWS CIS v.1.2.0 - 3.4'
               ],
               'filterPattern' : "{ ($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy) }"
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for CloudTrail configuration changes',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to CloudTrail\'s configurations.',
               'vulnerability' : 'Monitoring changes to CloudTrail\'s configuration will help ensure sustained visibility to activities performed in the AWS account.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=104'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.5',
                  'AWS CIS v.1.2.0 - 3.5'
               ],
               'filterPattern' : "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for AWS Management Console authentication failures',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for failed console authentication attempts.',
               'vulnerability' : 'Monitoring failed console logins may decrease lead time to detect an attempt to brute force acredential, which may provide an indicator, such as source IP, that can be used in other event correlation.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=108'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.6',
                  'AWS CIS v.1.2.0 - 3.6'
               ],
               'filterPattern' : "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs ',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for customer created CMKs which have changed state to disabled or scheduled deletion.',
               'vulnerability' : 'Data encrypted with disabled or deleted keys will no longer be accessible.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=112'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.7',
                  'AWS CIS v.1.2.0 - 3.7'
               ],
               'filterPattern' : "{ ($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }"
         },

         {
               'name' : 'Ensure a log metric filter and alarm exist for S3 bucket policy changes',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for changes to S3 bucket policies.',
               'vulnerability' : 'Monitoring changesto S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=108'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.8',
                  'AWS CIS v.1.2.0 - 3.8'
               ],
               'filterPattern' : "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for AWS Config configuration changes ',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to CloudTrail\'s configurations.',
               'vulnerability' : 'Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=120'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.9',
                  'AWS CIS v.1.2.0 - 3.9'
               ],
               'filterPattern' : "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }}"
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for security group changes',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingressand egress traffic within a VPC. It is recommended that a metric filter and alarm be established changes to Security Groups.',
               'vulnerability' : 'Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=124'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.10',
                  'AWS CIS v.1.2.0 - 3.10'
               ],
               'filterPattern' : "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. NACLs are used as a stateless packet filter to control ingress and egress traffic for subnets within a VPC. It is recommended that a metric filter and alarm be established for changes made to NACLs.',
               'vulnerability' : 'Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=128'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.11',
                  'AWS CIS v.1.2.0 - 3.11'
               ],
               'filterPattern' : "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for changes to network gateways',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Network gateways are required to send/receive traffic to a destination outside of a VPC. It is recommended that a metric filter and alarm be established for changes to network gateways.',
               'vulnerability' : 'Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=132'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.12',
                  'AWS CIS v.1.2.0 - 3.12'
               ],
               'filterPattern' : "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for route table changes',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Routing tables are used to route network traffic between subnets and to network gateways. It is recommended that a metric filter and alarm be established for changes to route tables.',
               'vulnerability' : 'Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=136'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.13',
                  'AWS CIS v.1.2.0 - 3.13'
               ],
               'filterPattern' : "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
         },
         {
               'name' : 'Ensure a log metric filter and alarm exist for VPC changes',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is possible to have more than 1 VPC within an account, in addition it is also possible to create a peer connection between 2 VPCs enabling network traffic to route between VPCs. It is recommended that a metric filter and alarm be established for changes made to VPCs.',
               'vulnerability' : 'Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=140'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.14',
                  'AWS CIS v.1.2.0 - 3.14'
               ],
               'filterPattern' : "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
         },
         {
               'name' : 'Ensure a log metric filter and alarm exists for AWS Organizations changes',
               'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for AWS Organizations changes made in the master AWS Account.',
               'vulnerability' : 'Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or intentional modifications that may lead to unauthorized access or other security breaches. This monitoring technique helps you to ensure that any unexpected changes performed within your AWS Organizations can be investigated and any unwanted changes can be rolled back.',
               'remediation' : 'Follow the steps in the CIS Benchmark paper',
               'severity' : 'info',
               'links' : [
                  'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail.html',
                  'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_security_incident-response.html'
               ],
               'references' : [
                  'AWS CIS v.1.4.0 - 4.15'
                  
               ],
               'filterPattern' : "'{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = AcceptHandshake) || ($.eventName = AttachPolicy) || ($.eventName = CreateAccount) || ($.eventName = CreateOrganizationalUnit) || ($.eventName = CreatePolicy) || ($.eventName = DeclineHandshake) || ($.eventName = DeleteOrganization) || ($.eventName = DeleteOrganizationalUnit) || ($.eventName = DeletePolicy) || ($.eventName = DetachPolicy) || ($.eventName = DisablePolicyType) || ($.eventName = EnablePolicyType) || ($.eventName = InviteAccountToOrganization) || ($.eventName = LeaveOrganization) || ($.eventName = MoveAccount) || ($.eventName = RemoveAccountFromOrganization) || ($.eventName = UpdatePolicy) || ($.eventName = UpdateOrganizationalUnit)) }'"
         }
      ]
      
      for POL in POLICIES:
         compliant = False

         # -- go through all the cloudtrail logs, and look for one that has IsMultiRegionTrail set to true
         for region in regionList:
            for trail in self.cache['cloudtrail']['describe_trails'].get(region,{}).get('trailList',{}):
               if compliant == False: 
                  # -- only keep searching if it is non-compliant.  We just need a single trail that meets all requirements
                  if trail['IsMultiRegionTrail'] == True:
                     if self.cache['cloudtrail']['get_trail_status'].get(region,{})[trail['TrailARN']]['IsLogging'] == True:
                        for e in self.cache['cloudtrail']['get_event_selectors'].get(region,{})[trail['TrailARN']]['EventSelectors']:
                           if e['IncludeManagementEvents'] == True:
                              if e['ReadWriteType'] == 'All':
                                 for FF in self.cache['logs']['describe_metric_filters'].get(region,{}):
                                    for f in FF['metricFilters']:
                                       if f['logGroupName'] in trail.get('CloudWatchLogsLogGroupArn',''):
                                          if f['filterPattern'] == POL['filterPattern']:
                                             for MM in self.cache['cloudwatch']['describe_alarms'].get(region,{}):
                                                for m in MM['MetricAlarms']:
                                                   if f['filterName'] == m['MetricName']:
                                                         for a in m['AlarmActions']:
                                                            for t in self.cache['sns']['list_topics'].get(region,{}):
                                                               if t['TopicArn'] == a:
                                                                     compliant = True
         self.finding(POL,compliant,None) 
      
      # --------------------------------------
      policy = {
         'name' : 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports',
         'description' : 'The Network Access Control List (NACL) function provide stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to remote server administration ports, such as SSH to port 22 and RDP to port 3389.',
         'vulnerability' : 'Public access to remote server administration ports, such as 22 and 3389, increases resource attack surface and unnecessarily raises the risk of resource compromise.',
         'remediation' : 'Restrict the incomping IP ranges of the network access control to a smaller IP range.',
         'severity' : 'low',
         'links' : [
               'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html#nacl-rules'
         ],
         'references' : [
               'AWS CIS v.1.4.0 - 5.1'
         ]
      }

      for region in regionList:
         for N in p['ec2']['describe_network_acls'].get(region,{}):
            for n in N['NetworkAcls']:
               for e in n['Entries']:
                  FromPort = e.get('PortRange',{}).get('FromPort',0)
                  ToPort = e.get('PortRange',{}).get('ToPort',65535)
                  
                  if e['Egress'] == False and e['RuleAction'] == 'allow' and e['CidrBlock'] in ['0.0.0.0/0','::/0'] and ((FromPort <= 22 and ToPort >= 22) or (FromPort <= 3389 and ToPort >= 3389)):
                     self.finding(policy,0,{ 'region' : region, 'NetworkAclId' : n['NetworkAclId'], 'Entries' : e })
                  else:
                     self.finding(policy,1,{ 'region' : region, 'NetworkAclId' : n['NetworkAclId'], 'Entries' : e })

      # --------------------------------------
      policy = {
         'name' : 'Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports',
         'description' : 'Security groups that are configured to allow port 22 (SSH) from the internet.',
         'vulnerability' : 'Removing unfettered connectivity to remote console services, such as SSH, reduces a server''s exposure to risk',
         'remediation' : 'Restrict the incomping IP ranges of the security groups to a smaller IP range, or alternatively, remove the security group.',
         'severity' : 'high',
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=144'
         ],
         'references' : [
               'AWS CIS v.1.4.0 - 5.2',
               'AWS CIS v.1.2.0 - 4.1',
               'AWS CIS v.1.2.0 - 4.2',
         ]
      }
      for region in regionList:
         for s in self.security_groups('IpPermissions',region):
            FromPort = s['FromPort']
            ToPort = s['ToPort']
            if ((FromPort <= 22 and ToPort >= 22) or (FromPort <= 3389 and ToPort >= 3389)) and s['IpRange'] in ['0.0.0.0/0','::/0']:
               self.finding(policy,0,s)
            else:
               self.finding(policy,1,s)

      # -----------------------------
      policy = {
         'name' : 'Ensure the default security group of every VPC restricts all traffic',
         'description' : 'Configuring all VPC default security groups to restrict all traffic will encourage least privilege security group development and mindful placement of AWS resources into security groups which will in-turn reduce the exposure of those resources.',
         'vulnerability' : 'The default security group allows very open permissions, and could inadvertently be applied to a resource, exposing that resource to the internet.',
         'remediation' : 'Remove any rules from the default security group.',
         'severity' : 'low',
         'references' : [
               'AWS CIS v.1.4.0 - 5.3',
               'AWS CIS v.1.2.0 - 4.3'
         ],
         'links' : [
               'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=148'
         ]
      }    
      for region in regionList:
         compliance = 1
         evidence = {}
         for s in self.security_groups('IpPermissions',region):
               if s['GroupName'] == 'default':
                  compliance = 0
                  evidence = { 'region' : region, 'GroupId' : s['GroupId']}
         for s in self.security_groups('IpPermissionsEgress',region):
               if s['GroupName'] == 'default':
                  compliance = 0
                  evidence = { 'region' : region, 'GroupId' : s['GroupId']}

         self.finding(policy,compliance,evidence)

      # --------------------------------------------------------
      policy = {
         'name' : 'Ensure S3 Bucket Policy is set to deny HTTP requests',
         'description' : 'At the Amazon S3 bucket level, you can configure permissions through a bucket policy making the objects accessible only through HTTPS.',
         'vulnerability' : 'By default, Amazon S3 allows both HTTP and HTTPS requests. To achieve only allowing access to Amazon S3 objects through HTTPS you also have to explicitly deny access to HTTP requests. Bucket policies that allow HTTPS requests without explicitly denying HTTP requests will not comply with this recommendation.',
         'remediation' : 'Follow <a href="https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/">AWS Best Practices</a>.',
         'severity' : 'medium',
         'reference' : [
               'AWS CIS v1.4.0 - 2.1.2',
         ],
         'links' : [
            'https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/',
            'https://aws.amazon.com/blogs/security/how-to-use-bucket-policies-and-apply-defense-in-depth-to-help-secure-your-amazon-s3-data/',
            'https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3api/get-bucket-policy.html'
         ]
      }
      for bucket in self.cache['s3']['get_bucket_policy'].get('us-east-1',{}):
         compliance = 0
         bucket_policy = json.loads(self.cache['s3']['get_bucket_policy'].get('us-east-1',{})[bucket].get('Policy','{}'))
         for s in bucket_policy.get('Statement',[]):
            if s['Effect'] == 'Deny' and s['Principal'] == '*' and s['Action'] in ['s3:*','s3:GetObject'] and s.get('Condition',{}).get('Bool',{}).get('aws:SecureTransport','true') == 'false':
               compliance = 1

         self.finding(policy,compliance,bucket)

      # --------------------------------------------------------
      policy = {
         'name' : 'S3 buckets must not be publicly accessible',
         'description' : '<a href="https://aws.amazon.com/s3/">S3</a> is a core storage solution from AWS.  It is used in most services, and provides an secure and scalable storage solution for your application.  If configured correctly, S3 can host highly sensitive information.  Publically accessible S3 buckets will allow anyone on the internet to access any data stored in a S3 bucket',
         'vulnerability' : 'Data within the bucket could be exposed, resulting in a loss of confidentiality.  When other files (for example web site images) are stored, there is a risk that another website may be using your resources by linking to the public bucket, incurring additional charges to your account.  An attacker may be able to modify sensitive data (for example updating an invoice to be paid with new bank details).  An attacker may be able to inject their own data into the bucket (for example submitting a fake order through an EDI system).  An attacker may be able to delete sensitive data, resulting in a system outage.',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonS3/latest/user-guide/block-public-access.html">AWS Best Practices</a> to remediate the publically exposed bucket.',
         'severity' : 'high',
         'reference' : [
               'ASI.DP.001',
               'Trusted Advisor - Amazon S3 bucket permissions'
         ],
         'links' : [
               'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/block-public-access.html',
               'https://aws.amazon.com/premiumsupport/technology/trusted-advisor/best-practice-checklist/#Security'
         ]
      }
      for bucket in self.cache['s3']['get_bucket_policy'].get('us-east-1',{}):
         evidence = []
         compliance = 1
         bucket_policy = json.loads(self.cache['s3']['get_bucket_policy'].get('us-east-1',{})[bucket].get('Policy','{}'))
         for s in bucket_policy.get('Statement',[]):
            for Effect in self.lister(s['Effect']):
               for Principal in self.lister(s['Principal']):
                  #for Action in self.lister(s['Action']):
                        #for Resource in self.lister(s['Resource']):
                           # 5 
                  if Effect == 'Allow' and (Principal == {'AWS' : '*'} or Principal == '*'):
                        evidence.append({bucket : bucket_policy.get('Statement',[]) })
                        compliance = 0

         for g in self.cache['s3']['get_bucket_acl'].get('us-east-1',{})[bucket].get('Grants',[]):
               if g['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' or g['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/Authenticated Users':
                  compliance = 0
                  evidence.append({bucket : g })
                     
         self.finding(policy,compliance,evidence)    
      # --------------------------------------------------------
      policy = {
         'name' : 'GuardDuty must be enabled in all regions',
         'description' : 'Amazon GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior to protect your AWS accounts, workloads, and data stored in Amazon S3.',
         'vulnerability' : 'GuardDuty provides visibility on threats that may try to access your system.',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html">AWS Best Practices</a> to enable GuardDuty on all regions.',
         'severity' : 'medium',
         'references' : [
               'ASI.DP.2'
         ],
         'links' : [
               'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html'
         ]
      }
      
      for region in regionList:
         compliance = 0
         if len(self.cache['guardduty']['list_detectors'].get(region,{})) > 0:
               compliance = 1
         else:
               compliance = 0
               
         self.finding(policy,compliance,region)

      # --------------------------------------------------------
      policy = {
         'name' : 'IAM Roles with Admin Rights',
         'description' : 'IAM roles should have least privilege defined in its execution role, and only be able to perform very specific tasks.',
         'vulnerability' : 'If a role with high level access is compromised, it has the potential to cause severe business disruption to the AWS account.',
         'severity' : 'high',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html">AWS Best Practices</a> to restrict the roles.',
         'references' : [
               'ASI.IAM.001'
         ],
         'links' : [
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html',
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html'
         ]
      }
      
      for LR in self.cache['iam']['list_roles'].get('us-east-1',{}):
         for list_roles in LR['Roles']:
            compliance = 1
            for q in self.parsePermissions():
                  if 'RoleName' in q:
                     if q['RoleName'] == list_roles['RoleName'] and q['Effect'] == 'Allow' and q['Action'] == '*' and q['Resource'] == '*':
                        compliance = 0
                                          
            self.finding(policy,compliance,list_roles['RoleName'])

# --------------------------------------------------------
      policy = {
         'name' : 'IAM Roles with external access',
         'description' : 'IAM Roles with external access describes that an external AWS account (potentially unknown to you) may have access to your account.',
         'vulnerability' : 'An external account with access to your account could circumvent regular identify access management process, and gain unauthorised access to your account.',
         'severity' : 'high',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html">AWS Best Practices</a> to restrict the roles.',
         'references' : [
               'ASI.IAM.004'
         ],
         'links' : [
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html',
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html'
         ]
      }
      for LR in self.cache['iam']['get_account_authorization_details'].get('us-east-1',{}):
         for roles in LR['RoleDetailList']:
            compliance = 1
            for statement in roles['AssumeRolePolicyDocument']['Statement']:
               if statement['Effect'] == 'Allow':
                  if type(statement['Principal']) == list:
                     for p in statement['Principal']:
                        if 'AWS' in p:
                           compliance = 0
                  else:
                     if 'AWS' in statement['Principal']:
                           compliance = 0
               self.finding(policy,compliance,{ roles['RoleName'] : statement } )

# --------------------------------------------------------
      policy = {
         'name' : 'IAM Groups with Admin Rights',
         'description' : 'IAM groups should have least privilege defined in its execution role, and only be able to perform very specific tasks.',
         'vulnerability' : 'If a group with high level access is compromised, it has the potential to cause severe business disruption to the AWS account.',
         'severity' : 'high',
         'remediation' : 'Follow <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html">AWS Best Practices</a> to restrict the roles.',
         'references' : [
               'ASI.IAM.002'
         ],
         'links' : [
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html',
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html'
         ]
      }
      
      for LG in self.cache['iam']['list_groups'].get('us-east-1',{}):
         for list_groups in LG['Groups']:
            compliance = 1
            for q in self.parsePermissions():
                  if 'GroupName' in q:
                     if q['GroupName'] == list_groups['GroupName'] and q['Effect'] == 'Allow' and q['Action'] == '*' and q['Resource'] == '*':
                        compliance = 0
                                          
            self.finding(policy,compliance,list_groups['GroupName'])

      # --------------------------------------------------------

      policy = {
         'name' : 'IAM entities with access to update Lambda functions',
         'description' : 'Any entity that is capable of updating a Lambda function is capable of potentially executing code running as the Lambda function.',
         'vulnerability' : 'Privilege escalation issues could occur if an unauthorised user is able to update a Lambda function.',
         'severity' : 'medium',
         'remediation' : 'Update the user or role permissions, by adjusting group memberships, or by adjusting the policies attached to the users, groups or roles.',
         'references' : [
               'ASI.IAM.005'
         ],
         'links' : [
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html'
         ]
      }

      entities = {
         'UserName' : {},
         'RoleName' : {}
      }

      for LG in self.cache['iam']['list_users'].get('us-east-1',{}):
         for list_users in LG['Users']:
            UserName = list_users['UserName']
            entities['UserName'][UserName] = 1
      for LG in self.cache['iam']['list_roles'].get('us-east-1',{}):
         for list_roles in LG['Roles']:
            RoleName = list_roles['RoleName']
            entities['RoleName'][RoleName] = 1

      evidence = {}
      for q in self.parsePermissions():
         for e in entities:
            for g in entities[e]:
               if e in q:
                  if not e in evidence:
                     evidence[e] = {}
                  if not g in evidence[e]:
                     evidence[e][g] = []
                  if q[e] == g and q['Effect'] == 'Allow' and (q['Action'] == '*' or q['Action'] == 'lambda:*' or q['Action'] == 'lambda:UpdateFunction'):
                     entities[e][g] = 0
                     evidence[e][g].append(q)

      for e in entities:
         for g in entities[e]:             
            self.finding(policy,entities[e][g],evidence[e][g])

      # --------------------------------------------------------

      policy = {
         'name' : 'IAM entities with access to update DynamoDB tables',
         'description' : 'Any entity that is capable of updating a DynamoDB table is capable of potentially altering the integrity of data in the tables.',
         'vulnerability' : 'Unauthorised access to DynamoDB tables can result in a loss of data (data breaches), or the modification of sensitive data.',
         'severity' : 'medium',
         'remediation' : 'Update the user or role permissions, by adjusting group memberships, or by adjusting the policies attached to the users, groups or roles.',
         'references' : [
               'ASI.IAM.006'
         ],
         'links' : [
               'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html'
         ]
      }

      entities = {
         'UserName' : {},
         'RoleName' : {}
      }

      for LG in self.cache['iam']['list_users'].get('us-east-1',{}):
         for list_users in LG['Users']:
            UserName = list_users['UserName']
            entities['UserName'][UserName] = 1
      for LG in self.cache['iam']['list_roles'].get('us-east-1',{}):
         for list_roles in LG['Roles']:
            RoleName = list_roles['RoleName']
            entities['RoleName'][RoleName] = 1

      evidence = {}
      for q in self.parsePermissions():
         for e in entities:
            for g in entities[e]:
               if e in q:
                  if not e in evidence:
                     evidence[e] = {}
                  if not g in evidence[e]:
                     evidence[e][g] = []
                  if q[e] == g and q['Effect'] == 'Allow' and (q['Action'] == '*' or q['Action'] == 'dynamodb:*' or q['Action'] in ['dynamodb:GetItem','dynamodb:GetRecords','dynamodb:UpdateItem','dynamodb:UpdateTable','dynamodb:PutItem','dynamodb:DeleteTable']):
                     entities[e][g] = 0
                     evidence[e][g].append(q)

      for e in entities:
         for g in entities[e]:             
            self.finding(policy,entities[e][g],evidence[e][g])

      # --------------------------------------------------------
      policy = {
         'name' : 'Application Load Balancer (ALB) listener allows connections over HTTP',
         'description' : 'Load balancers that listen on an HTTP port will not encrypt data while in transit.',
         'vulnerability' : 'When a load balancer operates over HTTP, any data it transmits is in clear text.  There is a high probability that the data can be intercepted and be compromised.',
         'remediation' : 'Create an <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html">HTTPS</a> listener for your load balancer.',
         'references' : [
               'ASI.NET.002'
         ],
         'links' : [
               'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html'
         ],
         'severity' : 'high',
      }
      for region in regionList:
         for EE in self.cache['elbv2']['describe_load_balancers'].get(region,{}):
            for elbv2 in EE['LoadBalancers']:
               if elbv2 != []:
                  compliance = 1

                  if 'describe_listeners' in elbv2:
                     for listener in elbv2['describe_listeners']:
                           if listener['Protocol'] == 'HTTP':
                              compliance = 0

                  self.finding(policy, compliance , {'region' : region, 'type' : 'elbv2', 'LoadBalancerName' : elbv2['LoadBalancerName'] })

         for EE in self.cache['elb']['describe_load_balancers'].get(region,{}):
            for elb in EE['LoadBalancerDescriptions']:
               if elb != []:
                  compliance = 1
                  
                  if 'ListenerDescriptions' in elb:
                        for listener in elb['ListenerDescriptions']:
                           if listener['Listener']['Protocol'] == 'HTTP':
                              compliance = 0
                  self.finding(policy, compliance , {'region' : region, 'type' : 'elb', 'LoadBalancerName' : elb['LoadBalancerName'] })

      # --------------------------------------------------------     
      policy = {
         'name' : 'Application Load Balancer (ALB) utilizing weak ciphers',
         'description' : 'Load Balancers running with the right encryption level ensures confidentiality of data being transmitted.',
         'vulnerability' : 'Vulnerabilities are detected in ciphers, that would allow the encrypted data to be easily decrypted, resulting in a loss of confidentiality.',
         'remediation' : 'Follow the <a href="https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html">steps</a> on the AWS website to improve the ciphers.',
         'references' : [
               'ASI.NET.003'
         ],
         'links' : [
               'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html'
         ],
         'severity' : 'high',
      }
      for region in regionList:
         for elbv2 in self.cache['elbv2']['describe_load_balancers'].get(region,{}):
               if elbv2 != []:
                  compliance = 1

                  if 'describe_listeners' in elbv2:
                     for listener in elbv2['describe_listeners']:
                           
                           if listener['Protocol'] == 'HTTPS':
                              if listener['SslPolicy'] == 'ELBSecurityPolicy-TLS-1-0-2015-04':
                                 compliance = 0

                              self.finding(policy, compliance , {'region' : region, 'type' : 'elbv2', 'LoadBalancerName' : elbv2['LoadBalancerName'] ,'SslPolicy' : listener.get('SslPolicy','')})

      # ----------------------------------

      policy = {
         'name'  : 'Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed',
         'description' : 'To enable HTTPS connections to your website or application in AWS, you need an SSL/TLS server certificate. You can use ACM or IAM to store and deploy server certificates. Use IAM as a certificate manager only when you must support HTTPS connections in a region that is not supported by ACM. IAM securely encrypts your private keys and stores the encrypted version in IAM SSL certificate storage. IAM supports deploying server certificates in all regions, but you must obtain your certificate from an external provider for use with AWS. You cannot upload an ACM certificate to IAM. Additionally, you cannot manage your certificates from the IAM Console.',
         'vulnerability' : 'Removing expired SSL/TLS certificates eliminates the risk that an invalid certificate will be deployed accidentally to a resource such as AWS Elastic Load Balancer (ELB), which can damage the credibility of the application/website behind the ELB. As a best practice, it is recommended to delete expired certificates.',
         'severity' : 'medium',
         'remediation' : 'Follow <a href="https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/">AWS Best practices</a> to rotate access keys.',
         'references' : [
               'AWS CIS v.1.4.0 - 1.19'
         ],
         'links' : [
            'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html',
            'https://docs.aws.amazon.com/cli/latest/reference/iam/delete-server-certificate.html'
         ]
      }

      for c in p['iam']['list_server_certificates']['us-east-1']:
         for cert in c['ServerCertificateMetadataList']:
            if (dateutil.parser.parse(cert['Expiration']) - dt.datetime.now().astimezone()).total_seconds() > 0:
               self.finding(policy,1,cert)
            else:
               self.finding(policy,0,cert)

      if not policy['name'] in self.findings:
         self.finding(policy,1)

   # ======================================================================================
   def parsePermissions(self):
      """
      parsePermissions will read all permissions for users and roles, and print out the individual policy permissions they have

      """
      perm = []

      # == cycle through all users ==
      for UU in self.cache['iam']['list_users'].get('us-east-1',{}):
         for u in UU['Users']:
            UserName = u['UserName']
            # -- find all inline policies
            if UserName in self.cache['iam']['list_user_policies'].get('us-east-1',{}):
                  
                  for P in self.cache['iam']['list_user_policies'].get('us-east-1',{})[UserName]:
                     for PolicyName in P['PolicyNames']:

                        for q in self.flattenStatements(self.cache['iam']['get_user_policy'].get('us-east-1',{})[UserName + ':' + PolicyName]['PolicyDocument']['Statement']):
                           q['source'] = 'get_user_policy'
                           q['UserName'] = UserName
                           q['PolicyName'] = PolicyName
                           q['Entity'] = u['Arn']
                           perm.append(q)

            # -- find all policies attached
            for PP in self.cache['iam']['list_attached_user_policies'].get('us-east-1',{})[UserName]:
               for p in PP['AttachedPolicies']:
                  PolicyName = p['PolicyName']
                  poly = self.cache['iam']['get_policy_version'].get('us-east-1',{})[PolicyName]['PolicyVersion']
                  for q in self.flattenStatements(poly['Document']['Statement']):
                     q['source'] = 'list_attached_user_policies'
                     q['UserName'] = UserName
                     q['PolicyName'] = PolicyName
                     q['Entity'] = u['Arn']
                     perm.append(q)

            # -- find all groups
            for LG in self.cache['iam']['list_groups'].get('us-east-1',{}):
               for list_groups in LG['Groups']:
                  GroupName = list_groups['GroupName']
                  for GG in self.cache['iam']['get_group'].get('us-east-1',{})[GroupName]:
                     for g in GG['Users']:
                        if UserName == g['UserName']:
                           # -- find all policies attached to the groups
                           for PP in self.cache['iam']['list_attached_group_policies'].get('us-east-1',{})[GroupName]:
                              for p in PP['AttachedPolicies']:
                                 PolicyName = p['PolicyName']
                                 poly = self.cache['iam']['get_policy_version'].get('us-east-1',{})[PolicyName]['PolicyVersion']
                                 for q in self.flattenStatements(poly['Document']['Statement']):
                                    q['source'] = 'list_attached_group_policies'
                                    q['GroupName'] = GroupName
                                    q['UserName'] = UserName
                                    q['PolicyName'] = PolicyName
                                    q['Entity'] = u['Arn']
                                    perm.append(q)

                           # -- do groups have inline policies?
                           if GroupName in self.cache['iam']['list_group_policies']:
                                 for PolicyName in self.cache['iam']['list_group_policies'][GroupName]:                            
                                    for q in self.flattenStatements(self.cache['iam']['get_group_policy'].get('us-east-1',{})[GroupName + ':' + PolicyName]['Statement']):
                                       q['source'] = 'get_group_policy'
                                       q['GroupName'] = GroupName
                                       q['UserName'] = UserName
                                       q['PolicyName'] = PolicyName
                                       q['Entity'] = u['Arn']
                                       perm.append(q)

      # == cycle through all roles
      for R in self.cache['iam']['list_roles'].get('us-east-1',{}):
         for r in R['Roles']:
            
            RoleName = r['RoleName']

            # -- find all policies attached to the roles
            for S in self.cache['iam']['list_attached_role_policies'].get('us-east-1',{})[RoleName]:
               for p in S['AttachedPolicies']:
                  PolicyName = p['PolicyName']

                  poly = self.cache['iam']['get_policy_version'].get('us-east-1',{})[PolicyName]['PolicyVersion']
                  for q in self.flattenStatements(poly['Document']['Statement']):
                     q['source'] = 'list_attached_role_policies'
                     q['RoleName'] = RoleName
                     q['PolicyName'] = PolicyName
                     q['Entity'] = r['Arn']
                     perm.append(q)
            # -- do roles have inline policies?
            if RoleName in self.cache['iam']['list_role_policies'].get('us-east-1',{}):
                  for D in self.cache['iam']['list_role_policies'].get('us-east-1',{})[RoleName]:
                     for PolicyName in D['PolicyNames']:
                        for q in self.flattenStatements(self.cache['iam']['get_role_policy'].get('us-east-1',{})[RoleName + ':' + PolicyName]['PolicyDocument']['Statement']):
                           q['source'] = 'get_role_policy'
                           q['RoleName'] = RoleName
                           q['PolicyName'] = PolicyName
                           q['Entity'] = r['Arn']
                           perm.append(q)

      return perm

   def flattenStatements(self,s):

      flat = []

      if type(s) == dict:
         s = [s]

      for s1 in s:
         for qqq in s1:
               if not qqq in ['Effect','Action','Resource','Sid','Condition']:
                  print('flattenStatements *** ERROR **' + qqq)
                  print(s1)
                  exit(1)


         effect = []
         if s1['Effect'] == list:
               effect = s1['Effect']
         else:
               effect.append(s1['Effect'])

         action = []
         if type(s1['Action']) == list:
               action = s1['Action']
         else:
               action.append(s1['Action'])

         resource = []            
         if type(s1['Resource']) == list:
               resource = s1['Resource']
         else:
               resource.append(s1['Resource'])


         for e in effect:
               for a in action:
                  for r in resource:
                     flat.append({
                           'Sid'       : s1.get('Sid'),
                           'Effect' : e,
                           'Action' : a,
                           'Resource' : r,
                           'Condition'       : s1.get('Condition')

                     })
      return flat

   def comparer(self,data,value):
      c = False
      if type(data) == str:
         c = data == value
      else:
         for d in data:
               if d == value:
                  c = True
         return False           
      return c

   def ulify(self,elements):
      string = "<ul>\n"
      for s in elements:
         if 'http' in s:
               string += '<li><a href="' + str(s) + '">' + str(s) + '</a></li>\n'
         else:
               string += '<li>' + str(s) + '</li>\n'
      string += "</ul>"
      return string

   def finding(self,policy,compliance,evidence = {}):
      name = policy['name']
      if not name in self.findings:
         self.findings[name] = {}
         self.findings[name][0] = []
         self.findings[name][1] = []
         self.findings[name]['description'] = policy.get('description','')
         self.findings[name]['severity'] = policy.get('severity','info')
         self.findings[name]['remediation'] = policy.get('remediation','')
         self.findings[name]['vulnerability'] = policy.get('vulnerability','')
         self.findings[name]['references'] = self.ulify(policy.get('references',[]))
         self.findings[name]['links'] = self.ulify(policy.get('links',[]))
   
      self.findings[name][compliance].append(evidence)
      
   def lister(self,input):
      if type(input) == list:
         return input
      else:
         return [input]


   