import argparse
from os import access
import jmespath
import json
import logging
import os.path
import yaml
import collections.abc
from mako.template import Template
import datetime
import markdown
from collector import *

class policy:
    def __init__(self):
        self.file_path = os.path.dirname(os.path.realpath(__file__))
        
        with open(self.file_path + '/policies.yaml') as y:
            self.policies = yaml.safe_load(y)
            logging.info('policies.yaml loaded')

    # the merge function will create a custom data type, making the parsing of the data easier
    def merge(self,C):
        def accessanalyzer_list_analyzers(C):
            out = {}
            for region in C['accessanalyzer'].get('list_analyzers',[]):
                if not region in out:
                    out[region] = []

                if len(C['accessanalyzer'].get('list_analyzers',{}).get(region,[])) == 0:
                    out[region].append({ 'status' : 'MISSING'})
                else:
                    out[region] = C['accessanalyzer']['list_analyzers'][region]


            return out

        def s3(C):
            out = {}
            for bucket in C['s3'].get('get_bucket_location',{}).get('us-east-1',[]):
                
                # -- figure out the location
                region = C['s3']['get_bucket_location']['us-east-1'][bucket]
                if region == None:
                    region = 'us-east-1'
                if not region in out:
                    out[region] = []

                blob = {
                    'bucket' : bucket
                }

                # public access check
                for x in ['get_bucket_accelerate_configuration','get_bucket_acl','get_bucket_intelligent_tiering_configuration','get_bucket_location','get_bucket_logging','get_bucket_notification','get_bucket_notification_configuration','get_bucket_request_payment','get_bucket_versioning','list_bucket_analytics_configurations','list_bucket_intelligent_tiering_configurations','list_multipart_uploads','list_object_versions','list_objects','list_objects_v2']:
                    y = C['s3']['_public_s3_bucket']['us-east-1'].get(bucket,{})
                    blob[x] = y.get(x,False)

                # -- public access block
                for x in ['BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets']:
                    y = C['s3']['get_public_access_block']['us-east-1'].get(bucket,{})
                    blob[x] = y.get(x,False)
                    
                # -- get_bucket_versioning
                gbv = C['s3']['get_bucket_versioning']['us-east-1'][bucket]
                for x in ['Status','MFADelete']:
                    blob[x] = gbv.get(x,'') == 'Enabled'

                # -- get_bucket_encryption
                gbe = C['s3']['get_bucket_encryption']['us-east-1'][bucket]
                
                if 'Rules' in gbe:
                    for x in gbe['Rules']:
                        blob['ApplyServerSideEncryptionByDefault'] = x['ApplyServerSideEncryptionByDefault']
                else:
                    blob['ApplyServerSideEncryptionByDefault'] = False

                out[region].append(blob)
            return out

        def get_ebs_encryption_by_default(C):
            out = {}
            for region in C['ec2'].get('get_ebs_encryption_by_default',[]):
                if not region in out:
                    out[region] = [
                        { 'EbsEncryptionByDefault' : C['ec2']['get_ebs_encryption_by_default'].get('EbsEncryptionByDefault',False) }
                    ]

            return out

        def ec2_describe_snapshots(C):
            out = {}
            for region in C['ec2'].get('describe_snapshots',[]):
                if not region in out:
                    out[region] = []
                for s in C['ec2']['describe_snapshots'][region]:
                    if not '_exception' in s:
                        s['_StartTime_ageDays'] = (datetime.datetime.today() - datetime.datetime.fromtimestamp(s['StartTime'])).days
                        out[region].append(s)
                    
            return out

        def kms_get_key_rotation_status(C):
            out = {}
            for region in C['kms'].get('get_key_rotation_status',[]):
                if not region in out:
                    out[region] = []
                for s in C['kms']['get_key_rotation_status'][region]:
                    if type(C['kms']['get_key_rotation_status'][region][s]) == bool:
                        out[region].append( { '_keyId' : s, '_status' : C['kms']['get_key_rotation_status'][region][s] })
                    else:
                        out[region].append( { '_keyId' : s, '_status' : False })
                            
            return out

        def keyvalue(x):
            out = {}
            for region in x:
                if not region in out:
                    out[region] = []

                for y in x[region]:
                    out[region].append({'key' : y, 'value' : x[region][y] })

            return out

        def flatten(d, parent_key='', sep='_'):
            items = []
            for k, v in d.items():
                new_key = parent_key + sep + k if parent_key else k
                if isinstance(v, collections.abc.MutableMapping):
                    items.extend(flatten(v, new_key, sep=sep).items())
                else:
                    items.append((new_key, v))
            return dict(items)

        def flattenStatements(s):
            flat = []

            if type(s) == dict:
                s = [s]

            for s1 in s:
                for qqq in s1:
                    if not qqq in ['Effect','Action','Resource','Sid','Condition','NotAction']:
                        print('flattenStatements *** ERROR **' + qqq)
                        print(s1)
                        exit(1)


                effect = []
                if s1['Effect'] == list:
                    effect = s1['Effect']
                else:
                    effect.append(s1['Effect'])

                action = []
                if type(s1.get('Action')) == list:
                    action = s1['Action']
                else:
                    action.append(s1.get('Action'))

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

        def security_groups(C):
            # process the security groups into something a bit more managable
            flat = {}
            grp = {}
            
            for region in C:
                if not region in flat:
                    flat[region] = []

                for t in ['IpPermissionsEgress','IpPermissions']:
                    grp['_direction'] = t
                    for sg in C[region]:
                        if not '_exception' in sg:
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
                                    
                                    flat[region].append(cp)

                                for i in r['Ipv6Ranges']:
                                    grp['IpRange'] = i['CidrIpv6']

                                    cp = {}
                                    for g in grp:
                                        cp[g] = grp[g]
                                    
                                    flat[region].append(cp)
            return flat

        def describe_configuration_recorders(C):
            out = {}
            for region in C['config']['describe_configuration_recorders']:
                if not region in out:
                    out[region] = []

                if len(C['config']['describe_configuration_recorders'][region]) == 0:
                    out[region].append( {
                        "name": "**unknown**",
                        "roleARN": None,
                        "recordingGroup": {
                            "allSupported": None,
                            "includeGlobalResourceTypes": None,
                            "resourceTypes": []
                        },
                        "describe_configuration_recorder_status": {
                            "name": "**unknown**",
                            "lastStartTime": -1,
                            "recording": False,
                            "lastStatus": None,
                            "lastStatusChangeTime": -1
                        }
                    }
         )
                else:
                    for c in C['config']['describe_configuration_recorders'][region]:
                        c['describe_configuration_recorder_status'] = False
                        
                        for s in C['config']['describe_configuration_recorder_status'].get(region,{}):
                            if s['name'] == c['name']:
                                c['describe_configuration_recorder_status'] = s
                                
                        out[region].append(c)

            return out

        def describe_trails(C):
            out = {}

            for region in C['describe_trails']:
                if not region in out:
                    out[region] = []

                if len(C['describe_trails'].get(region,[])) == 0:
                    out[region].append({ 'Name' : '** Missing Trail **'})
                else:
                    for trail in C['describe_trails'][region]:
                        if not '_exception' in trail:
                            x = C['get_trail_status'][region][trail['TrailARN']]
                            for a in x:
                                trail[f'get_trail_status_{a}'] = x[a]

                            for x in C['get_event_selectors'][region][trail['TrailARN']]:
                                for a in x:
                                    # TODO - this may not be the best approach -- there can be multiple event selectors...
                                    trail[f'get_event_selectors_{a}'] = x[a]
                                
                            out[region].append(trail)
                    
            return out

        def guardduty_list_detectors(C):
            out = {}
            for region in C['guardduty']['list_detectors']:
                if not region in out:
                    out[region] = []

                cnt = 0
                for x in C['guardduty']['list_detectors'][region]:
                    if not '_exception' in x:
                        cnt += 1

                out[region].append({ 'count' : cnt })

            return out

        def describe_instances(C):
            out = {}

            for region in C['ec2']['describe_instances']:
                if not region in out:
                    out[region] = []

                for R in C['ec2']['describe_instances'][region]:
                    if not '_exception' in R:
                        for i in R['Instances']:

                            # -- find the SSM instance info
                            for y in C['ssm']['describe_instance_information'][region]:
                                if y['InstanceId'] == i['InstanceId']:
                                    for a in y:
                                        i[f'ssm_{a}'] = y[a]
                                    
                            out[region].append(i)
            return out

        C['custom'] = {
            'iam_get_credential_report' : {
                'us-east-1' : []
            },
            'iam_list_policies' : {
                'us-east-1' : []
            },
            'iam_get_account_authorization_details_RoleDetailList' : {
                'us-east-1' : []
            },
            'ec2_describe_security_groups'      : security_groups(C['ec2']['describe_security_groups']),
            'cloudtrail_describe_trails'        : describe_trails(C['cloudtrail']),
            'ec2_describe_instances'            : describe_instances(C),
            'iam_AccountPasswordPolicy'         : keyvalue(C['iam']['AccountPasswordPolicy']),
            's3'                                : s3(C),
            'get_ebs_encryption_by_default'     : get_ebs_encryption_by_default(C),
            'guardduty_list_detectors'          : guardduty_list_detectors(C),
            'describe_snapshots'                : ec2_describe_snapshots(C),
            'get_key_rotation_status'           : kms_get_key_rotation_status(C),
            'accessanalyzer_list_analyzers'     : accessanalyzer_list_analyzers(C),
            'describe_configuration_recorders'  : describe_configuration_recorders(C)
        }

        print(json.dumps(C['custom']['describe_configuration_recorders'],indent=4))
        #exit(0)

        # == merge user accounts
        for blob in C['iam']['get_credential_report']['us-east-1']:
            blob['_list_user_policies'] = C['iam'].get('list_user_policies',{}).get('us-east-1',{}).get(blob['user'],{})
            blob['_list_user_policies_count'] = len(blob['_list_user_policies'])
            blob['_list_attached_user_policies'] = C['iam'].get('list_attached_user_policies',{}).get('us-east-1',{}).get(blob['user'],{})
            blob['_list_attached_user_policies_count'] = len(blob['_list_attached_user_policies'])

            # == list_virtual_mfa_devices
            blob['_list_virtual_mfa_devices'] = jmespath.search('[?User.Arn==\'' + blob['arn'] + '\']',C['iam']['list_virtual_mfa_devices'].get('us-east-1',{}))
            C['custom']['iam_get_credential_report']['us-east-1'].append(blob)    

        # == parse all IAM policies
        # == cycle through all users ==
        for u in C['iam']['list_users'].get('us-east-1',{}):
            
            UserName = u['UserName']
            # -- find all inline policies
            if UserName in C['iam']['list_user_policies'].get('us-east-1',{}):
                
                for PolicyName in C['iam']['list_user_policies'].get('us-east-1',{})[UserName]:
                    for q in flattenStatements(C['iam']['get_user_policy'].get('us-east-1',{})[UserName + ':' + PolicyName]['Statement']): #['PolicyDocument']['Statement']):
                        q['source'] = 'get_user_policy'
                        q['UserName'] = UserName
                        q['PolicyName'] = PolicyName
                        q['Entity'] = u['Arn']
                        C['custom']['iam_list_policies']['us-east-1'].append(q)

            # -- find all policies attached
            for p in C['iam']['list_attached_user_policies'].get('us-east-1',{})[UserName]:
                PolicyName = p['PolicyName']
                poly = C['iam']['get_policy_version'].get('us-east-1',{})[PolicyName]#['PolicyVersion']
                for q in flattenStatements(poly['Document']['Statement']):
                    q['source'] = 'list_attached_user_policies'
                    q['UserName'] = UserName
                    q['PolicyName'] = PolicyName
                    q['Entity'] = u['Arn']
                    C['custom']['iam_list_policies']['us-east-1'].append(q)

            # -- find all groups
            for list_groups in C['iam']['list_groups'].get('us-east-1',{}):
                
                GroupName = list_groups['GroupName']
                for GG in C['iam']['get_group'].get('us-east-1',{})[GroupName]:
                    for g in GG['Users']:
                        if UserName == g['UserName']:
                            # -- find all policies attached to the groups
                            for p in C['iam']['list_attached_group_policies'].get('us-east-1',{})[GroupName]:
                                PolicyName = p['PolicyName']
                                poly = C['iam']['get_policy_version'].get('us-east-1',{})[PolicyName]#['PolicyVersion']
                                for q in flattenStatements(poly['Document']['Statement']):
                                    q['source'] = 'list_attached_group_policies'
                                    q['GroupName'] = GroupName
                                    q['UserName'] = UserName
                                    q['PolicyName'] = PolicyName
                                    q['Entity'] = u['Arn']
                                    C['custom']['iam_list_policies']['us-east-1'].append(q)

                        # -- do groups have inline policies?
                        if GroupName in C['iam']['list_group_policies']:
                                for PolicyName in C['iam']['list_group_policies'][GroupName]:                            
                                    for q in flattenStatements(C['iam']['get_group_policy'].get('us-east-1',{})[GroupName + ':' + PolicyName]['Statement']):
                                        q['source'] = 'get_group_policy'
                                        q['GroupName'] = GroupName
                                        q['UserName'] = UserName
                                        q['PolicyName'] = PolicyName
                                        q['Entity'] = u['Arn']
                                        C['custom']['iam_list_policies']['us-east-1'].append(q)

        # == cycle through all roles
        for r in C['iam']['list_roles'].get('us-east-1',{}):
            RoleName = r['RoleName']

            # -- find all policies attached to the roles
            for p in C['iam']['list_attached_role_policies'].get('us-east-1',{})[RoleName]:
                PolicyName = p['PolicyName']

                poly = C['iam']['get_policy_version'].get('us-east-1',{})[PolicyName]
                for q in flattenStatements(poly['Document']['Statement']):
                    q['source'] = 'list_attached_role_policies'
                    q['RoleName'] = RoleName
                    q['PolicyName'] = PolicyName
                    q['Entity'] = r['Arn']
                    C['custom']['iam_list_policies']['us-east-1'].append(q)

            # -- do roles have inline policies?
            if RoleName in C['iam']['list_role_policies'].get('us-east-1',{}):
                for PolicyName in C['iam']['list_role_policies'].get('us-east-1',{})[RoleName]:
                    for q in flattenStatements(C['iam']['get_role_policy'].get('us-east-1',{})[RoleName + ':' + PolicyName]['Statement']):
                        q['source'] = 'get_role_policy'
                        q['RoleName'] = RoleName
                        q['PolicyName'] = PolicyName
                        q['Entity'] = r['Arn']
                        C['custom']['iam_list_policies']['us-east-1'].append(q)


        # get_account_authorization_details
        for x in C['iam']['get_account_authorization_details']['us-east-1']:
            if not '_exception' in x:
                for y in x['RoleDetailList']:
                    for s in y['AssumeRolePolicyDocument']['Statement']:
                        n = flatten(s)
                        for z in ['Path','RoleName','RoleId','Arn','CreateDate','AttachedManagedPolicies']:
                            n[z] = y[z]
                        C['custom']['iam_get_account_authorization_details_RoleDetailList']['us-east-1'].append(n)

    def process(self,C, debug = None):

        self.merge(C)

        evidence = {
            'summary' : {},
            'detail' : {},
            'policy' : {},
            'top' : { 'total' : 0.0, 'totalok' : 0.0 , 'score' : 0.0}
        }

        for policy in self.policies:
            if debug == None or debug == policy:
                logging.info(f'Checking policy {policy}')

                evidence['detail'][policy] = { 0 : [], 1 : [] }
                evidence['summary'][policy] = { 'total' : 0.0 , 'totalok' : 0.0, 'score' : 0.0 }

                cfg = self.policies[policy]

                # -- QA check the policies
                if not 'name' in cfg:
                    cfg['name'] = policy
                    logging.warning(f'Missing \'name\' in policy {policy}')

                for tag in ['description','remediation','vulnerability','rating']:
                    if not tag in cfg:
                        logging.warning(f'Missing \'{tag}\' in policy {policy}')
                        cfg[tag] = '** unknown **'
                    else:
                        if tag != 'rating':
                            cfg[tag] = markdown.markdown(cfg[tag])

                evidence['policy'][policy] = cfg

                # == find all the assets in question from the "asset" field
                assets = []

                x = jmespath.search(cfg['asset']['path'],C)
                for region in x:
                    if 'flatten' in cfg['asset']:
                        flatten = cfg['asset']['flatten']
                        for y in x[region]:
                            if not '_exception' in y:
                                for z in y[flatten]:
                                    z['_region'] = region
                                    assets.append(z)
                    else:
                        for z in x[region]:
                            if not '_exception' in z:
                                z['_region'] = region
                                assets.append(z)

                if debug:
                    logging.info('*************************************')
                    logging.info(' ** ASSETS **')
                    logging.info('*************************************')
                    for x in assets:
                        logging.info(json.dumps(x))
                        logging.info('--')
                    print('=============================')
                # == is there a filter?
                assets2 = []
                if 'filter' in cfg['asset']:
                    if debug:
                        logging.info('filter = ' + cfg['asset']['filter'])

                    assets2 = jmespath.search(cfg['asset']['filter'],assets)
                else:
                    assets2 = assets
                if debug:
                    logging.info('*************************************')
                    logging.info(' ** ASSETS WITH FILTER **')
                    logging.info('*************************************')
                    for x in assets2:
                        logging.info(json.dumps(x))
                        logging.info('--')
                    print('=============================')
                # == go through the assets (this is the total section)
                assets3 = []
                for x in assets2:
                    assets3.append(jmespath.search(cfg['asset']['fields'],x))

                if debug:
                    logging.info('*************************************')
                    logging.info(' ** ASSETS WITH FIELDS **')
                    logging.info('*************************************')
                    for x in assets3:
                        logging.info(json.dumps(x))
                        logging.info('--')
                    logging.info('=============================')
                
                # == Check every asset to see if it is compliant or not
                for a in assets3:

                    if jmespath.search(cfg['policy'],[a]):
                        evidence['detail'][policy][0].append(a)
                    else:
                        evidence['detail'][policy][1].append(a)
                    
                evidence['summary'][policy]['totalok'] = len(evidence['detail'][policy][1])
                evidence['summary'][policy]['total'] = len(evidence['detail'][policy][0]) + len(evidence['detail'][policy][1])
                if evidence['summary'][policy]['total'] != 0:

                    # == calculate the score
                    totalok = evidence['summary'][policy]['totalok']
                    total = evidence['summary'][policy]['total']

                    # -- linear
                    #x = totalok / total

                    # -- inverse log
                    x = (total ** (totalok / total)) / total

                    evidence['summary'][policy]['score'] =  x
                else:
                    evidence['summary'][policy]['score'] = 1

                if debug:
                    logging.info('score    : ' + str(evidence['summary'][policy]['totalok']) + ' / ' + str(evidence['summary'][policy]['total']) + ' = ' + str(evidence['summary'][policy]['score']))
                
        # We average the percentages because some controls may have a lot more resources, which then skews the percentages
        weight = {
            'Critical' : 5,
            'High' : 3,
            'Medium' : 2,
            'Low' : 1,
            'Info' : 0
        }
        for p in evidence['summary']:
            rating = evidence['policy'][p]['rating']
            evidence['top']['total'] += weight[rating]
            evidence['top']['totalok'] += evidence['summary'][p]['score'] * weight[rating]

            if evidence['top']['total'] != 0:
                evidence['top']['score'] = evidence['top']['totalok'] / evidence['top']['total']
            else:
                evidence['top']['score'] = 1


        return evidence
        
    def arguments(self,parser):
        #x = parser.parse_args()
        
        try:
            parser.add_argument('--collect',help='The filename where the collected data file should be stored', required=True)
        except:
            # the parameter is already there
            x = 1

        parser.add_argument('--evidence',help = 'Where to save the evidence file to')
        parser.add_argument('--report',help = 'Where to save the report (HTML) file to')
        parser.add_argument('--debug',help = 'Used to debug policies')

    def report(self,X,C):
        data = {
            'scanneddate'      : C['sts']['get_caller_identity']['us-east-1']['ResponseMetadata']['HTTPHeaders']['date'],
            'account'   : C['sts']['get_caller_identity']['us-east-1']['Account'],
            'date'      : datetime.datetime.now().strftime('%Y-%m-%d'),
            'time'      : datetime.datetime.now().strftime('%H:%M:%S')
        }

        tmp = Template(filename=self.file_path + '/report.html')
        return tmp.render(evidence = X, data = data)

    def execute(self,args,file = None):

        C = collector()
        if file == None:
            file = args.collect
        
        logging.info('Policy input file (--collect) : ' + file)

        try:
            with open(file,'rt') as fc:
                C.cache = json.load(fc)
        except:
            logging.error(f'Cannot read -- {file}')
            exit(1)

        # -- now we parse the policies
        if args.evidence or args.report:
            evidence = self.process(C.cache,args.debug)
        
        if args.evidence:
            C.fileio(args.evidence,json.dumps(evidence,indent=4))

        if args.report:
            C.fileio(args.report,self.report(evidence,C.cache))


if __name__ == '__main__':
    logging.basicConfig(level = logging.INFO)
    logging.info('')
    logging.info('=====================================================')
    logging.info('')
    logging.info('  AWS Security Info - Cloud Policy Parser')
    logging.info('  by Phil Massyn - @massyn')
    logging.info('  https://www.awssecurity.info')
    logging.info('')
    logging.info('====================================================')
    logging.info('')

    p = policy()
    parser = argparse.ArgumentParser(description='AWS Security Info - Cloud Policy Parser')
    p.arguments(parser)
    args = parser.parse_args()
    p.execute(args)
