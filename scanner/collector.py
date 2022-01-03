import argparse
import boto3
import time
from botocore.config import Config
import datetime
import yaml
import json
import os.path
import os
from urllib.parse import urlparse
import jmespath
import logging
import csv
import dateutil

class collector:
    def __init__(self):
        self.data_file = ''
        self.cache = {}
        self.counter = 0
        self.errors = 0
        self.start_time = time.time()
        self.written = False
        self.aws_access_key_id      = None
        self.aws_secret_access_key  = None
        self.aws_session_token      = None

        # Find the file path
        file_path = os.path.dirname(os.path.realpath(__file__))
        self.file_path = file_path

        logging.info(f'Reading the seed files from {file_path}')
        # -- read the collector file into memory - we will need to parse it to find what we'll be doing
        try:
            with open(f'{file_path}/collector.yaml','rt') as y:
                self.data = yaml.safe_load(y)
        except:
            logging.error(f' ** UNABLE TO READ THE YAML FILE {file_path}/collector.yaml')
            exit(0)

        # Seed the initial file, if global.json exists
        if os.path.isfile(f'{file_path}/global.json'):
            logging.info('Seeding the initial data dump with global.json...')
            self.read_json(f'{file_path}/global.json')
        else:
            logging.warning('global.json does not exist, so we will load everything from AWS. This may take a bit longer...')
            self.cache = {}

    def authenticate(self,aws_access_key_id = None,aws_secret_access_key = None,aws_session_token = None):
        self.aws_access_key_id      = aws_access_key_id
        self.aws_secret_access_key  = aws_secret_access_key
        self.aws_session_token      = aws_session_token

        self.cache_call('sts','get_caller_identity')
        
    def convert_timestamp(self,item_date_object):
        if isinstance(item_date_object, (datetime.date,datetime.datetime)):
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

    def fileio(self,fi,data = None):
        if 'sts' in self.cache:
            account = self.cache['sts']['get_caller_identity']['us-east-1']['Account']
        else:
            account = ''
        
        if '%a' in fi and account == '':
            logging.warning(' ** unable to read or write anything until we know what account this is **')
            return None
        else:
            datestamp = datetime.datetime.now().strftime("%Y-%m-%d")
            filename = fi.replace('%a',account).replace('%d',datestamp)

            self.last_file_name_read = filename

            if data == None:
                # -- is this s3?
                if 's3://' in filename:
                    logging.info(f' -- reading file from S3 -- {filename}')
                    p = urlparse(filename, allow_fragments=False)
                    bucket = p.netloc
                    if p.query:
                        key = p.path.lstrip('/') + '?' + p.query
                    else:
                        key = p.path.lstrip('/')

                    try:
                        return boto3.client('s3').get_object(Bucket=bucket, Key=key)['Body']
                    except:
                        logging.warning(f' ** Unable to read the s3 file - {filename}')
                        return None
                else:
                    logging.info(f' -- reading file from localdisk -- {filename}')
                    try:
                        with open(filename,'rt') as j:
                            return j.read()
                    except:
                        logging.warning(' !! cannot load {filename}')
                        return None
            else:
                # -- is this s3?
                if 's3://' in filename:
                    logging.info(f' -- writing file to S3 -- {filename}')
                    p = urlparse(filename, allow_fragments=False)
                    bucket = p.netloc
                    if p.query:
                        key = p.path.lstrip('/') + '?' + p.query
                    else:
                        key = p.path.lstrip('/')
                  
                    # TODO = s3 authentication will be tricky -- think about this for a sec...
                    boto3.client('s3').put_object(Body=data, Bucket=bucket, Key=key)
                else:
                    logging.info(f' -- writing file to local disk -- {filename}')
                    with open(filename,'wt') as f:
                        f.write(data)
                        f.close()

    def write_json(self):
        if self.written == True:
            return   
        self.fileio(self.data_file,json.dumps(self.cache,indent = 4, default=self.convert_timestamp))
        self.written = True

    def read_json(self,fi = None):
        x = self.fileio(fi)
        if x != None:
            self.cache = json.loads(x)

            self.data_file = self.last_file_name_read

    def collect(self):
        self.collect_priority(1)
        self.collect_priority(2)
        self.collect_priority(3)
        self.collect_priority(4)
        self.collect_priority(5)
        self.collect_custom()

        self.build_global('global.json')

        return self.cache

    def collect_custom(self):
        if not 'AccountPasswordPolicy' in self.cache['iam']:
            self.cache['iam']['AccountPasswordPolicy'] = {}
            self.cache['iam']['AccountPasswordPolicy']['us-east-1'] = self.iam_AccountPasswordPolicy()
            self.written = False

        if not 'get_credential_report' in self.cache['iam']:
            self.cache['iam']['get_credential_report'] = {}
            self.cache['iam']['get_credential_report']['us-east-1'] = self.iam_get_credential_report()
            self.written = False

        region = 'us-east-1'
        if not '_public_s3_bucket' in self.cache['s3']:
            self.cache['s3']['_public_s3_bucket'] = {}
        if not region in self.cache['s3']['_public_s3_bucket']:
            self.cache['s3']['_public_s3_bucket'][region] = {}
        for s in self.cache['s3']['list_buckets'][region]:
            if not s['Name'] in self.cache['s3']['_public_s3_bucket'][region]:
                self.cache['s3']['_public_s3_bucket'][region][s['Name']] = self.check_if_S3_bucket_is_public(s['Name'])
                self.written = False

        # -- check the CloudTrail S3 buckets
        for region in self.cache['cloudtrail']['describe_trails']:
            for ct in self.cache['cloudtrail']['describe_trails'][region]:
                if 'S3BucketName' in ct:
                    if not ct['S3BucketName'] in self.cache['s3']['_public_s3_bucket']['us-east-1']:
                        self.cache['s3']['_public_s3_bucket']['us-east-1'][ct['S3BucketName']] = self.check_if_S3_bucket_is_public(ct['S3BucketName'])
                        self.written = False
        
        self.write_json()      

    def collect_priority(self,P):
        logging.info(f'Collecting priority {P}')
        for service in self.data:
            for function in self.data[service]:
                priority = self.data[service][function].get('priority',3)

                if P == priority:
                    self.do_collection(service,function,**self.data[service][function])
                    self.write_json()

    def do_collection(self,service,function,**KW):
        if KW.get('region') == None:
            r = self.cache['ec2']['describe_regions']

            core_regionList = sorted([x['RegionName'] for x in r['us-east-1']])
            regionList = core_regionList
        else:
            regionList = [ 'us-east-1' ]  # us-east-1 must always be included - it contains our core IAM functions.

        for region in regionList:
            if 'loop' in KW:
                # -- find the data for this loop
                if not 'service' in KW['loop']:
                    logging.error(f'loop parameter specified without a service - {service} - {function}')
                if not 'function' in KW['loop']:
                    logging.error(f'loop parameter specified without a function - {service} - {function}')
                if not KW['loop']['service'] in self.cache:
                    logging.error(f'You specified a service in a loop that does not exist in the data file - {service} - {function}')
                if not KW['loop']['function'] in self.cache[KW['loop']['service']]:
                    logging.error(f'You specified a function in a loop that does not exist in the data file - {service} - {function}')

                for x in self.cache[KW['loop']['service']][KW['loop']['function']][region]:
                    if not '_exception' in x:
                        vars = {
                            'ACCOUNTID' : self.cache['sts']['get_caller_identity']['us-east-1']['Account']
                        }
                        if type(x) == str:
                            vars['VAR'] = x
                        else:
                            for v in KW['loop']['variables']:
                                vars[v] = jmespath.search(KW['loop']['variables'][v],x)

                        if 'identifier' in KW:
                            identifier = KW['identifier']
                            for v in vars:
                                identifier = identifier.replace(f'${v}',vars[v])
                        else:
                            identifier = None

                        if 'parameter' in KW:
                            parameter = json.dumps(KW['parameter'])
                            for v in vars:
                                parameter = parameter.replace(f'${v}',vars[v])
                        else:
                            parameter = "{}"

                        if 'loop2' in KW:
                            # -- start of loop 2
                            # -- find the data for this loop
                            if not 'service' in KW['loop2']:
                                logging.error(f'loop2 parameter specified without a service - {service} - {function}')
                            if not 'function' in KW['loop2']:
                                logging.error(f'loop2 parameter specified without a function - {service} - {function}')
                            if not KW['loop2']['service'] in self.cache:
                                logging.error(f'You specified a service in a loop2 that does not exist in the data file - {service} - {function}')
                            if not KW['loop2']['function'] in self.cache[KW['loop2']['service']]:
                                logging.error(f'You specified a function in a loop2 that does not exist in the data file - {service} - {function}')

                            if 'lookup' in KW['loop2']:
                                lookup = KW['loop2']['lookup']
                                for v in vars:
                                    lookup = lookup.replace(f'${v}',vars[v])
                                looplist = self.cache[KW['loop2']['service']][KW['loop2']['function']][region][lookup]
                            else:
                                looplist = self.cache[KW['loop2']['service']][KW['loop2']['function']][region]
                                
                            for y in looplist:
                                if not '_exception' in y:
                                    if type(y) == str:
                                        vars['VAR'] = y
                                    else:
                                        for v in KW['loop2']['variables']:
                                            vars[v] = jmespath.search(KW['loop2']['variables'][v],y)

                                    if 'identifier' in KW:
                                        identifier = KW['identifier']
                                        for v in vars:
                                            identifier = identifier.replace(f'${v}',vars[v])
                                    else:
                                        identifier = None

                                    if 'parameter' in KW:
                                        parameter = json.dumps(KW['parameter'])
                                        for v in vars:
                                            parameter = parameter.replace(f'${v}',vars[v])
                                    else:
                                        parameter = "{}"

                                self.cache_call(service,function,region,json.loads(parameter),identifier,KW.get('flatten'))
                            # -- end of loop 2
                        else:    
                            self.cache_call(service,function,region,json.loads(parameter),identifier,KW.get('flatten'))
            else:
                self.cache_call(service,function,region,KW.get('parameter',{}),KW.get('identifier'),KW.get('flatten'))
        self.write_json()

    def cache_call(self,client,function,region = 'us-east-1',parameter = {}, identifier = None,flatten = None):
        if not client in self.cache:
            self.cache[client] = {}
        if not function in self.cache[client]:
            self.cache[client][function] = {}

        if type(region) == list:
            regionList = region
         
            for region in regionList:
                self.cache_call(client,function,region,parameter,identifier,flatten)

            return self.cache[client][function]

        if identifier != None:
            if not region in self.cache[client][function]:
                self.cache[client][function][region] = {}
            if not identifier in self.cache[client][function][region]:
                z = self.aws_call(client,function,region,parameter,flatten)
                self.cache[client][function][region][identifier] = z
            return self.cache[client][function][region][identifier]

        else:
            if not region in self.cache[client][function]:
                z = self.aws_call(client,function,region,parameter,flatten)
                self.cache[client][function][region] = z
            return self.cache[client][function]

    def aws_call(self,client,function,region = 'us-east-1',parameter = {},flatten = None):
        """
            This function only makes a call to AWS, and return the data - no processing at all.
            client
            function
            region
            parameter
        """

        self.counter += 1
        self.written = False
        logging.info('===========================================================================================')
        logging.info('aws call - {client} / {function} - {region} - ({elapsed} seconds, {counter} API calls, {errors} errors)'.format(client = client,function = function, region = region, counter = self.counter, elapsed = int(time.time() - self.start_time), errors = self.errors))
        if parameter != {}:
            logging.info(parameter)

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
                    if flatten != None:
                        if flatten in a:
                            for I in a[flatten]:
                                output.append(I)
                        else:
                            logging.error(f'You specificed a parameter to flatten, but it was not found in the data seen from AWS - {flatten}')
                    else:
                        output.append(a)
            except Exception as e:
                logging.error(' ** AWS ERROR ** ' + str(e))
                output.append( { '_exception' : str(e) })
                self.errors += 1
                if 'ThrottlingException' in str(e):
                    logging.warning(' ** sleeping for 10 seconds, then try again **')
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
                logging.error(' ** AWS ERROR ** ' + str(e))
                if 'ThrottlingException' in str(e):
                    logging.warning(' ** sleeping for 10 seconds, then try again **')
                    time.sleep(10)
                    return self.aws_call(client,function,region,parameter)
                
                if 'ExpiredToken' in str(e):
                    self.write_json()
                    exit(1)

                result = { '_exception' : str(e) }
                self.errors += 1
            if flatten in result:
                return result[flatten]
            else:
                return result

    def build_global(self,output):
        # this function will generate the global.json file - this is essentially an initial seed
        # of the data dump, for objects that are truely global, like AWS Managed IAM policies.
        # There's no need for your system to query all 900 of them.  We can do it once, and save the file.
        # If it exists, we'll just read that, and save a bunch of data transfer charges.
        # If for whatever reason you'd like to refresh it, just delete global.json, and it will be recreated.

        if not os.path.isfile(self.file_path + '/' + output):
            logging.info('Creating a new global.json file...')
            G = { 'iam' : {
                    'get_policy_version' : { 
                        'us-east-1' : {

                        }
                    }
                }
            }

            # -- find all global IAM policies
            for P in self.cache['iam']['list_policies']['us-east-1']:
                if 'arn:aws:iam::aws:policy/' in P['Arn']:
                    PolicyName = P['PolicyName']
                    G['iam']['get_policy_version']['us-east-1'][PolicyName] = self.cache['iam']['get_policy_version']['us-east-1'][PolicyName]

            # save the file down
            with open(self.file_path + '/' + output,'wt') as f:
                f.write(json.dumps(G,indent = 4, default=self.convert_timestamp))
                f.close()
        else:
            logging.info('Not writing global.json, since there is already one.')

    # ============= Custom collections
    def iam_AccountPasswordPolicy(self):
        logging.info('custom - iam_AccountPasswordPolicy')
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

    def iam_get_credential_report(self):
        logging.info('custom - iam_get_credential_report')
        def age(dte):
            if dte == 'not_supported' or dte == 'N/A' or dte == 'no_information':
                return -1
            else:
                result = datetime.date.today() - dateutil.parser.parse(dte).date()
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

    def check_if_S3_bucket_is_public(self,bucket):
        logging.info('custom - check if S3 bucket is public - ' + bucket)
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

    def arguments(self,parser):
        parser.add_argument('--collect',help='The filename where the collected data file should be stored', required=True)
        parser.add_argument('--nocollect',help='If specified, the script will skip the collection', action='store_true')
        parser.add_argument('--aws_access_key_id', help='aws_access_key_id', default = None)
        parser.add_argument('--aws_secret_access_key', help='aws_secret_access_key', default = None)
        parser.add_argument('--aws_session_token', help='aws_session_token', default = None)

        parser.add_argument('--rolearn', help='Role ARN for assume role', default = None)
        parser.add_argument('--externalid', help='Optional external id assume role', default = None)

    def execute(self,args):
        logging.info('Output file (--collect) : ' + args.collect)
        logging.info('nocollect : ' + str(args.nocollect))

        

        if not args.nocollect:
            a = args.aws_access_key_id
            b = args.aws_secret_access_key
            c = args.aws_session_token

            # -- determine the authentication type
            if args.rolearn != None or args.externalid != None:
                logging.info('** Authenticating by switching role')
                (a,b,c) = assume_role(a,b,c,args.rolearn,args.externalid)

            if a != None or b != None or c != None:
                logging.info('** Authenticating with access keys...')
            else:
                logging.info('** Default authentication')
            
            self.authenticate(a,b,c)
            self.read_json(args.collect)
            
            self.collect()

def assume_role(a,b,c,RoleArn,ExternalId):
    try:
        if ExternalId != None:
            assume_role = boto3.client('sts',
                aws_access_key_id = a,
                aws_secret_access_key = b,
                aws_session_token = c
            ).assume_role(
                RoleArn=RoleArn,
                RoleSessionName='string',
                ExternalId=ExternalId
            )
        else:
            assume_role = boto3.client('sts',
                aws_access_key_id = a,
                aws_secret_access_key = b,
                aws_session_token = c
            ).assume_role(
                RoleArn=RoleArn,
                RoleSessionName='string'
            )

        aws_access_key_id       = assume_role['Credentials']['AccessKeyId'];
        aws_secret_access_key   = assume_role['Credentials']['SecretAccessKey'];
        aws_session_token       = assume_role['Credentials']['SessionToken'];
        logging.info ('** assume-role succeeded **')
        return (aws_access_key_id,aws_secret_access_key,aws_session_token)
    except:
        logging.critical('Unable to switch role')
        exit(1)

if __name__ == '__main__':
    logging.basicConfig(level = logging.INFO)
    logging.info('')
    logging.info('=====================================================')
    logging.info('')
    logging.info('  AWS Security Info - Cloud Configuration Collector')
    logging.info('  by Phil Massyn - @massyn')
    logging.info('  https://www.awssecurity.info')
    logging.info('')
    logging.info('====================================================')
    logging.info('')

    C = collector()
    parser = argparse.ArgumentParser(description='AWS Security Info - Cloud Configuration Collector')
    
    C.arguments(parser)
    args = parser.parse_args()
    C.execute(args)

    logging.info(' ** All done **')
