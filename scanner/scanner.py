import argparse
import datetime as dt
from datetime import datetime
from collector import collector
from policies import policies
from report import report
from sts import sts
import json
import os.path
import os
from urllib.parse import urlparse
import boto3
import urllib.request
import urllib.parse
import sys

def slackMe(webHook = None,message = None):
   if webHook != None:
      print(' -- sending slack message -- ' + message)
      req = urllib.request.Request(
         webHook,
         json.dumps({'text': message}).encode('utf-8'),
         {'Content-Type': 'application/json'}
      )
      resp = urllib.request.urlopen(req)
      response = resp.read()
      
      print(response)
   else:
      print(' -- Slack not configured -- ' + message)

def convert_timestamp(item_date_object):
   if isinstance(item_date_object, (dt.date,dt.datetime)):
      return item_date_object.timestamp()

def load_file(f):
   
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
         print('-- reading s3 --')
         return json.load(boto3.client('s3').get_object(Bucket=bucket, Key=key)['Body'])
      except:
         print(' ** Unable to read the s3 file - ' + f)
         return {}
   else:
      if os.path.isfile(f):
         
         with open(f,'rt') as j:
               output = json.load(j)
               j.close()

               return output
      else:
         print(' !! cannot load ' + f)
         return {}

def save_file(f,c,sign = False):

   # -- is this s3?
   if 's3://' in f:
      p = urlparse(f, allow_fragments=False)
      bucket = p.netloc
      if p.query:
         key = p.path.lstrip('/') + '?' + p.query
      else:
         key = p.path.lstrip('/')

      # TODO = s3 authentication will be tricky -- think about this for a sec...
      boto3.client('s3').put_object(Body=c, Bucket=bucket, Key=key, ContentType = 'text/html' )

      # should we generate a pre-signed url ?
      if sign:   
         response = boto3.client('s3').generate_presigned_url(
               'get_object',
               Params = {
                  'Bucket': bucket,
                  'Key'   : key
               },
               ExpiresIn = 86400
         )
         return response
   else:
      with open(f,'wt') as f:
         f.write(c)
         f.close()
      
      return None

def history(trackfile,c,p,slack = None):
   # -- are we tracking alerts - any changes to policies
   if trackfile:

      account = c.cache['sts']['get_caller_identity']['us-east-1']['Account']
      datestamp = datetime.utcnow().strftime("%Y-%m-%d")

      currentDT = dt.datetime.utcnow()
      now = currentDT.strftime("%Y-%m-%d %H:%M:%S")

      file = trackfile.replace('%a',account).replace('%d',datestamp)

      history = load_file(file)

      if history == {}:
         print ('new history file -- just update stuff')
         newfile = True
      else:
         newfile = False
      
      newhistory = {}
      for policy in p.findings:
         
         if not policy in newhistory:
               newhistory[policy] = {}
         
         # -1 unknown
         #  0 fail
         #  1 pass

         for state in [0,1]:
               for obj in p.findings[policy][state]:
                  o = str(obj)

                  o_history = history.get(policy,{}).get(o,{ 'firstseen' : now, 'state' : -1 })

                  if not o in newhistory[policy]:
                     newhistory[policy][o] = {
                              'firstseen' : o_history['firstseen'],
                              'lastseen' : now,
                              'laststate' : o_history['state'],
                              'state' : state
                           }

                  if o_history['state'] != state:
                     if state == 0 and newfile == False:
                           slackMe(slack,':warning: Account {account} - {policy} - {o}'.format(account = account,policy = policy, o = o))

      save_file(file,json.dumps(newhistory,indent = 4, default=convert_timestamp))

def create_managed_policy_cache(c,file):
   def convert_timestamp(item_date_object):
      if isinstance(item_date_object, (dt.date,dt.datetime)):
         return item_date_object.timestamp()
         
   if not os.path.exists(file):
      print(' ** creating cached managed policies : ' + file)
      new = { 'iam' : { 'get_policy_version' : { 'us-east-1' : {} }}}

      # -- Find the AWS managed policies
      for i in c.cache['iam']['list_policies']['us-east-1']:
         for p in i['Policies']:
            if 'arn:aws:iam::aws:' in p['Arn']:
               # -- now find the get_policy_version
               pv = c.cache['iam']['get_policy_version']['us-east-1'][p['PolicyName']]

               new['iam']['get_policy_version']['us-east-1'][p['PolicyName']] = pv
      
      with open(file,'wt') as f:
         f.write(json.dumps(new,indent=4, default=convert_timestamp))
         f.close()

def main():
   parser = argparse.ArgumentParser(description='AWS Security Info - Security Scanner')

   parser.add_argument('--aws_access_key_id', help='aws_access_key_id', default = None)
   parser.add_argument('--aws_secret_access_key', help='aws_secret_access_key', default = None)
   parser.add_argument('--aws_session_token', help='aws_session_token', default = None)

   parser.add_argument('--assumerole',help='The role name you are trying to switch to',default=False)
   parser.add_argument('--account',help='The AWS Account number you are trying to switch to')
   parser.add_argument('--externalid',help='The external ID required to complete the assume role')
   parser.add_argument('--json',help='The filename where the collected data file should be stored', required=True)
   parser.add_argument('--output',help='The filename of the output json findings (use %a for the AWS account id, and %d for a datestamp)')
   parser.add_argument('--html',help='The filename of the output html findings (use %a for the AWS account id, and %d for a datestamp)')
   parser.add_argument('--slack',help='Provide a Slack webhook for status reporting')
   parser.add_argument('--nocollect',help='Do not run the collector -- just parse the json file', action='store_true')
   parser.add_argument('--track',help='Specify a file that is used to keep track of all findings, and send slack alerts for all new alerts.')
   parser.add_argument('--organization',help='Specify your Organization account access role.  If this is found, the script will continue to find all child accounts, and try to switch the role to the child accounts')
   parser.add_argument('--regions',help='By default, all regions will be queried.  If you only operate in one (or a few) regions, you can limit the scope to only those regions. Specify --region region1,region2,retion3 etc.  Note that us-east-1 is always included.')

   args = parser.parse_args()
   print ('--- Starting ---')
   
   # -- what is the initial data load file?
   initial = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/initial.json'
   
   s = sts()

   a = args.aws_access_key_id
   b = args.aws_secret_access_key
   c = args.aws_session_token

   if not args.nocollect:
      print('*** AUTHENTICATING ***')
      if (args.assumerole == False):
         print (' - Connect directly...')   
      else:
         print (' - Trying to switch role...')
         (a,b,c) = s.assume_role(a,b,c,args.account,args.assumerole,args.externalid)
         if a == None:
               print('!!! UNABLE TO SWITCH ROLE !!!')
               exit(1)

      c = collect_account(a,b,c, json = args.json, html = args.html, output = args.output, track = args.track, slack = args.slack ,regions = args.regions, initial = initial)

   else:
      c = collector(a,b,c)
      if args.json:
         if '%a' in args.json and args.nocollect:
               print('** ERROR ** We cannot figure out what the account name is (%a) if you use the nocollect function')
               exit(1)

         c.read_json(args.json)

   create_managed_policy_cache(c,initial)   # add the AWS managed policies to a cache file -- this helps to reduce the time to collect stuff that should already be there

   account = c.cache['sts']['get_caller_identity']['us-east-1']['Account']
   
   # -- is there an organization?
   if args.organization:
      print(' Organization flag received')
      for f in c.cache['organizations']['list_accounts']['us-east-1']:
         for i in f['Accounts']:
            if i['Status'] == 'ACTIVE' and i['Id'] != account:
               accountId = i['Id']
               print(accountId)
               print (' - Trying to switch role...')
               try:
                  (a,b,c) = s.assume_role(a,b,c,accountId,args.organization,None)
                  if a == None:
                     print('!!! UNABLE TO SWITCH ROLE !!!')
                  else:
                     collect_account(a,b,c,json = args.json, html = args.html, output = args.output, track = args.track, slack = args.slack,regions = args.regions, initial = initial )
               except:
                  print('!!! UNABLE TO SWITCH ROLE !!!')
                  slackMe(args.slack,':x: Unable to switch role for *{account}*.'.format(account = accountId))
               

   print ('--- Completed ---')

def collect_account(a,b,c,**KW):
   # == collect the data
   c = collector(a,b,c)
   if KW['initial'] != None:
      try:
         print(' -- reading the initial file...')
         with open(KW['initial'],'rt') as j:
            c.cache = json.load(j)
            j.close()
      except:
         print(' !! initial file does not exist -- skipping !!')

   c.cache_call('sts','get_caller_identity')

   if KW['json'] != None:
      c.read_json(KW['json'])
   
   c.collect_all(KW['regions'])
   if KW['json'] != None:
      c.write_json()
   
   account = c.cache['sts']['get_caller_identity']['us-east-1']['Account']
   
   # == write the reports
   # the datestamp is fixed to Y-m-d - this is to allow for sorting, and having the newest first
   datestamp = datetime.utcnow().strftime("%Y-%m-%d")

   # == generate the list if findings from the policies defined
   p = policies(c.cache)
   p.execute()

   # -- if we need to generate some output, then we go through this section
   url = ''
   if KW['output'] or KW['html']:
      print('*** GENERATE REPORTS ***')
      
      r = report(p.findings, c.cache, True)
      if KW['html']:
         output = KW['html'].replace('%a',account).replace('%d',datestamp)
         print('Writing output html findings == ' + output) 
         out = r.generate()

         url = save_file(output,out,True)
         if url:
               print('Report URL will be valid for 24 hours ==> ' + url)
               slackMe(KW['slack'],':checkered_flag: Security audit report for <{url}|{account}> is now complete.'.format(account = account, url = url))

      if url == '':
         slackMe(KW['slack'],':white_check_mark: Security collection for *{account}* is now complete.'.format(account = account))

      if KW['output']:
         output = KW['output'].replace('%a',account).replace('%d',datestamp)
         print('Writing output json findings == ' + output)
         save_file(output,json.dumps(p.findings,indent = 4, default=convert_timestamp))

   if KW['track']:
      history(KW['track'],c,p,KW['slack'])
   
   return c

def lambda_handler(event, context):

   ### THIS PART IS DANGEROUS ####
   # Please, DEVELOPER - be VERY CAREFUL writing code where a lambda function calls itself... You run the risk of creating infite loops, 
   # running your function millions of times, and AWS would be happy to run it for you, AND SEND YOU THE BILL!
   region = os.environ['AWS_REGION']

   if isinstance(event,list):
      for i in event:
         # let the lambda call individual items
         response = boto3.client('lambda', region_name = region).invoke(
               FunctionName=context.function_name,
               Payload=json.dumps(i),
               InvocationType='Event'
         )
         print (response)
      return {
         'statusCode': 200,
         'body': json.dumps('Account messages sent')
      }
      
   
   # -- continue with normal calls

   slack_webhook = os.environ['SLACK_WEBHOOK']
   s3_bucket = os.environ['S3_BUCKET']

   if 'accountId' in event:
      # -- if we get an accountid, we need to switch role
      s = sts()
      (a,b,c) = s.assume_role(None,None,None,event['accountId'],'AWSSecurityInfoReadOnlyRole',event['externalId'])

      # -- do we need to overwrite the slack webhook ?  (maybe the client should be sent to a different account)
      if 'slack' in event:
         slack_webhook = event['slack']
         
      if a == None:
         slackMe(slack_webhook,':warning: Unable to switch role for {account}'.format(account = event['accountId']))
         exit(1)
   else:
      a = None
      b = None
      c = None

   c = collector(a,b,c)
   
   c.sts_get_caller_identity()
   account = c.cache['sts']['get_caller_identity']['us-east-1']['Account']

   # You may want to read the old cache for testing purposes
   #c.cache = load_file('s3://' + s3_bucket + '/cache-' + str(account) + '.json')

   c.collect_all()

   print('AWS Account is ' + str(account))
   # the datestamp is fixed to Y-m-d - this is to allow for sorting, and having the newest first
   datestamp = datetime.utcnow().strftime("%Y-%m-%d")

   # -- save the cache file
   save_file('s3://' + s3_bucket + '/cache-' + str(account) + '.json',json.dumps(c.cache,indent = 4, default=convert_timestamp))

   # == generate the list if findings from the policies defined
   p = policies(c.cache)
   p.execute()

   # -- do the history check here
   history('s3://' + s3_bucket + '/track-' + str(account) + '.json',c,p)

   # -- produce the report
   r = report(p.findings, c.cache)
   url = save_file('s3://' + s3_bucket + '/report-' + str(account) + '-' + datestamp + '.json',r.generate(),True)
   if url:
      slackMe(slack_webhook,':checkered_flag: Security audit report for <{url}|{account}> is now complete.'.format(account = account, url = url))

         
if __name__ == '__main__':
   main()