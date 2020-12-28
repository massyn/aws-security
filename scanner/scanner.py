import argparse
import datetime as dt
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

    parser.add_argument("--cache", help="Do not overwrite the json file - instead, read it and continue where you left off", action="store_true")
    parser.add_argument('--oj',help='The filename of the output json findings')
    parser.add_argument('--oh',help='The filename of the output html findings')

    args = parser.parse_args()
    
    s = sts()

    a = args.aws_access_key_id
    b = args.aws_secret_access_key
    c = args.aws_session_token

    if (args.assumerole == False):
        print ('Connect directly...')   
    else:
        print ('Trying to switch role...')
        (a,b,c) = s.assume_role(a,b,c,args.account,args.role,args.externalid)
        if a == None:
            print('** UNABLE TO SWITCH ROLE **')
            exit(1)

    c = collector(a,b,c)
    
    if args.cache:
        # refresh the file with any new items
        if os.path.isfile(args.json):
            c.read_json(args.json)
        c.collect_all()
        c.write_json(args.json)
    else:
        # collect all fresh, and save a cache
        c.collect_all()
        c.write_json(args.json)

    account = c.cache['sts']['get_caller_identity']['Account']
    print('AWS Account is ' + str(account))
            

    # -- if we need to generate some output, then we go through this section
    if args.oj or args.oh:    
        # == generate the policies
        p = policies(c.cache)
        p.execute()

        r = report(p.findings, c.cache)
        if args.oh:
            r.generate(args.oh)

        if args.oj:
            print('Writing output json findings...')
            with open(args.oj,'wt') as f:
                f.write(json.dumps(p.findings,indent = 4, default=convert_timestamp))
                f.close()
            

main()