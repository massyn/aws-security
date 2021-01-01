import argparse
import datetime as dt
from datetime import datetime
from collector import collector
from policies import policies
from report import report
from sts import sts
import json
import os.path

def convert_timestamp(item_date_object):
    if isinstance(item_date_object, (dt.date,dt.datetime)):
        return item_date_object.timestamp()

def main():
    parser = argparse.ArgumentParser(description='AWS Security Info - Security Scanner')

    parser.add_argument('--aws_access_key_id', help='aws_access_key_id', default = None)
    parser.add_argument('--aws_secret_access_key', help='aws_secret_access_key', default = None)
    parser.add_argument('--aws_session_token', help='aws_session_token', default = None)

    parser.add_argument('--assumerole',help='Attempt to switch role', action='store_true')
    parser.add_argument('--role',help='The role name you are trying to switch to')
    parser.add_argument('--account',help='The AWS Account number you are trying to switch to')
    parser.add_argument('--externalid',help='The external ID required to complete the assume role')
    parser.add_argument('--json',help='The filename where the collected data file should be stored',required = True)
    parser.add_argument('--oj',help='The filename of the output json findings (use %a for the AWS account id, and %d for a datestamp)')
    parser.add_argument('--oh',help='The filename of the output html findings (use %a for the AWS account id, and %d for a datestamp)')
    
    args = parser.parse_args()
    print ('--- Starting ---')
    s = sts()

    a = args.aws_access_key_id
    b = args.aws_secret_access_key
    c = args.aws_session_token

    print('*** AUTHENTICATING ***')
    if (args.assumerole == False):
        print (' - Connect directly...')   
    else:
        print (' - Trying to switch role...')
        (a,b,c) = s.assume_role(a,b,c,args.account,args.role,args.externalid)
        if a == None:
            print('!!! UNABLE TO SWITCH ROLE !!!')
            exit(1)

    c = collector(a,b,c)
    c.read_json(args.json)
    c.collect_all()
    c.write_json()

    # -- if we need to generate some output, then we go through this section
    if args.oj or args.oh:    
        print('*** GENERATE REPORTS ***')
        account = c.cache['sts']['get_caller_identity']['Account']
        print('AWS Account is ' + str(account))
        
        # the datestamp is fixed to Y-m-d - this is to allow for sorting, and having the newest first
        datestamp = datetime.now().strftime("%Y-%m-%d")

        # == generate the policies
        p = policies(c.cache)
        p.execute()

        r = report(p.findings, c.cache)
        if args.oh:
            output = args.oh.replace('%a',account).replace('%d',datestamp)
            print('Writing output html findings == ' + output) 
            r.generate(output)

        if args.oj:
            
            output = args.oj.replace('%a',account).replace('%d',datestamp)
            print('Writing output json findings == ' + output) 
            with open(output,'wt') as f:
                f.write(json.dumps(p.findings,indent = 4, default=convert_timestamp))
                f.close()
    print ('--- Completed ---')
            

main()