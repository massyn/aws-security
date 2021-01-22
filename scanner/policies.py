import json
import time
import datetime as dt

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
        
        for sg in self.cache['ec2']['describe_security_groups'][region]:
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

    def execute(self):
        print('*** POLICIES ***')
        
        p = self.cache
        # ------------------------------------------------------
        policy = {
            'name' : 'Avoid the use of the "root" account',
            'description' : 'The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html">root user</a> is the highest privileged, unrestricted account within your AWS landscape.  Because of the sensitivity of this account, it should not be used for normal day-to-day operations.',
            'vulnerability' : 'The root account represents unrestricted access to the entire account.  A compromise of the root account will mean a complete loss control of the account.  This can result in data leakage, or rogue resources being created (for example bitcoin mining), at the account owner\'s expense.',
            'remediation' : 'Avoid using the root account, and <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html">create a seperate IAM user</a> with the least-privilege policies applied.',
            'links' : [
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html',
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=11'
            ],
            'references' : [
                'AWS CIS v1.2.0 - 1.1'
            ]
        }
        
        for u in p['iam']['credentials']:
            if u['user'] == '<root_account>':
                evidence = {
                    'password_last_used' : u['password_last_used']
                }
                if u['_password_last_used_age'] == -1:
                    self.finding(policy,1,evidence)
                else:
                    self.finding(policy,0,evidence)
        # ---------------------------------------------------
        policy = {
            'name' : 'Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password',
            'description' : 'MFA (or <a href="https://en.wikipedia.org/wiki/Multi-factor_authentication">multi factor authentication</a>) refers to using an additional factor (like a security fob or a one-time password), in addition to the regular username and password to gain access to an account.',
            'vulnerability' : 'Without MFA, there is a higher probability of the account being compromised.',
            'remediation' : 'Follow the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html">AWS best practices</a> to configure MFA on your root account.',
            'links' : [
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html',
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=13'
            ],
            'references' : [
                'AWS CIS v.1.2.0 - 1.2'
            ]
        }
        for u in p['iam']['credentials']:
            if u['password_enabled'] == 'true':
                evidence = {
                    'user' : u['user']                 
                }
                if u['mfa_active'] == 'true':
                    self.finding(policy,1,evidence)
                else:
                    self.finding(policy,0,evidence)

        # ------------------------------------------------------
        policy = {
            'name' : 'Ensure credentials unused for 90 days or greater are disabled',
            'description' : 'Credentials refer to passwords or access keys.',
            'vulnerability' : 'Unused credentials indicate a user account that may not be in use.  Accounts that are not in use should be removed to reduce the risk of account compromise.',
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html">AWS Best practices</a> to remove unused credentials',
            'references' : [
                'AWS CIS v.1.2.0 - 1.3'
            ],
            'links' : [
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html',
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=16'
            ]
        }
        for u in p['iam']['credentials']:
            # -- console password
            if u['password_enabled'] == 'true':
                evidence = {
                    'user' : u['user'],
                    'password_last_used' : u['password_last_used']
                }
                if u['_password_last_used_age'] > 90 or u['_password_last_used_age'] == -1:
                    self.finding(policy,0,evidence)
                else:
                    self.finding(policy,1,evidence)

            # -- access key 1
            if u['access_key_1_active'] == 'true':
                evidence = {
                    'user' : u['user'],
                    'access_key_1_last_used_date' : u['access_key_1_last_used_date']
                }
                if u['_access_key_1_last_used_date_age'] > 90 or u['_access_key_1_last_used_date_age'] == -1:
                    self.finding(policy,0,evidence)
                else:
                    self.finding(policy,1,evidence)

            # -- access key 2
            if u['access_key_2_active'] == 'true':
                evidence = {
                    'user' : u['user'],
                    'access_key_2_last_used_date' : u['access_key_2_last_used_date']
                }
                if u['_access_key_2_last_used_date_age'] > 90 or u['_access_key_2_last_used_date_age'] == -1:
                    self.finding(policy,0,evidence)
                else:
                    self.finding(policy,1,evidence)

        # ------------------------------------------------------
        policy = {
            'name'  : 'Ensure access keys are rotated every 90 days or less',
            'description' : 'Rotating access keys is a security best practice to reduce the likelihood of account compromise.',
            'vulnerability' : 'Aging access keys, just like passwords, need to be rotated to reduce the risk of credentials leaking to unauthorised users, resulting in account compromise.',
            'remediation' : 'Follow <a href="https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/">AWS Best practices</a> to rotate access keys.',
            'references' : [
                'AWS CIS v.1.2.0 - 1.4'
            ],
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=18',
                'https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/'
            ]
        }

        for u in p['iam']['credentials']:
            # -- access key 1
            if u['access_key_1_active'] == 'true':
                evidence = {
                    'user' : u['user'],
                    'access_key_1_last_rotated' : u['access_key_1_last_rotated']
                }
                if u['_access_key_1_last_rotated_age'] > 90 or u['_access_key_1_last_rotated_age'] == -1:
                    self.finding(policy,0,evidence)
                else:
                    self.finding(policy,1,evidence)

            # -- access key 2
            if u['access_key_2_active'] == 'true':
                evidence = {
                    'user' : u['user'],
                    'access_key_2_last_rotated' : u['access_key_2_last_rotated']
                }
                if u['_access_key_2_last_rotated_age'] > 90 or u['_access_key_2_last_rotated_age'] == -1:
                    self.finding(policy,0,evidence)
                else:
                    self.finding(policy,1,evidence)
        # ------------------------------------------------------
        policy = {
            'name' : 'Ensure IAM password policy is set to a strong password',
            'description' : 'IAM Password Policy specifies the password complexity requirements for the AWS IAM users.',
            'vulnerability' : 'Weak password policies will cause users to select weak, easy to guess passwords.',
            'remediation' : '''Follow the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html">AWS Best Practices</a> to set an IAM Password Policy.<ul>
            
            <li>1.5 Ensure IAM password policy requires at least one uppercase letter</li>
            <li>1.6 Ensure IAM password policy require at least one lowercase letter</li>
            <li>1.7 Ensure IAM password policy require at least one symbol</li>
            <li>1.8 Ensure IAM password policy require at least one number</li>
            <li>1.9 Ensure IAM password policy requires minimum length of 14 or greater</li>
            <li>1.10 Ensure IAM password policy prevents password reuse (set to at least 24)</li>
            <li>1.11 Ensure IAM password policy expires passwords within 90 days or less</li>

            </ul>''',
            'references' : [
                'AWS CIS v.1.2.0 - 1.5',
                'AWS CIS v.1.2.0 - 1.6',
                'AWS CIS v.1.2.0 - 1.7',
                'AWS CIS v.1.2.0 - 1.8',
                'AWS CIS v.1.2.0 - 1.9',
                'AWS CIS v.1.2.0 - 1.10',
                'AWS CIS v.1.2.0 - 1.11'
            ],
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=20',
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html'
            ]
        }
        
        if p['iam']['policy']['require_uppercase_characters']:
            self.finding(policy,1,{ 'require_uppercase_characters' : p['iam']['policy']['require_uppercase_characters'] })
        else:
            self.finding(policy,0,{ 'require_uppercase_characters' : p['iam']['policy']['require_uppercase_characters'] })

        if p['iam']['policy']['require_lowercase_characters']:
            self.finding(policy,1,{ 'require_lowercase_characters' : p['iam']['policy']['require_lowercase_characters'] })
        else:
            self.finding(policy,0,{ 'require_lowercase_characters' : p['iam']['policy']['require_lowercase_characters'] })

        if p['iam']['policy']['require_symbols']:
            self.finding(policy,1,{ 'require_symbols' : p['iam']['policy']['require_symbols'] })
        else:
            self.finding(policy,0,{ 'require_symbols' : p['iam']['policy']['require_symbols'] })

        if p['iam']['policy']['require_numbers']:
            self.finding(policy,1,{ 'require_numbers' : p['iam']['policy']['require_numbers'] })
        else:
            self.finding(policy,0,{ 'require_numbers' : p['iam']['policy']['require_numbers'] })

        if p['iam']['policy']['minimum_password_length'] == None:
            self.finding(policy,0,{ 'minimum_password_length' : p['iam']['policy']['minimum_password_length'] })
        else:
            if p['iam']['policy']['minimum_password_length'] >= 14:
                self.finding(policy,1,{ 'minimum_password_length' : p['iam']['policy']['minimum_password_length'] })
            else:
                self.finding(policy,0,{ 'minimum_password_length' : p['iam']['policy']['minimum_password_length'] })

        if p['iam']['policy']['password_reuse_prevention'] == None:
            self.finding(policy,0,{ 'password_reuse_prevention' : p['iam']['policy']['password_reuse_prevention'] })
        else:
            if p['iam']['policy']['password_reuse_prevention'] >= 24:
                self.finding(policy,1,{ 'password_reuse_prevention' : p['iam']['policy']['password_reuse_prevention'] })
            else:
                self.finding(policy,0,{ 'password_reuse_prevention' : p['iam']['policy']['password_reuse_prevention'] })

        if p['iam']['policy']['max_password_age'] == None:
            self.finding(policy,0,{ 'max_password_age' : p['iam']['policy']['max_password_age'] })
        else:
            if p['iam']['policy']['max_password_age'] <= 90:
                self.finding(policy,1,{ 'max_password_age' : p['iam']['policy']['max_password_age'] })
            else:
                self.finding(policy,0,{ 'max_password_age' : p['iam']['policy']['max_password_age'] })

        # ------------------------------------------------------
        policy = {
            'name' : 'Ensure no root account access key exists',
            'description' : '<a href="https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html">Access keys</a> allow programatic access to your AWS account.  When the access keys are not well protected, it can allow unauthorised access to your AWS account.',
            'remediation' : 'Remove the root access keys.  <a href="https://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html">More information</a>',
            'vulnerability' : 'Access keys provide access to the AWS account without having to use a password or multi-factor authentication.  They can end up in source code, and pose a significant risk if not managed correctly.',
            'references' : [
                "AWS CIS v.1.2.0 - 1.12"
            ],
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=34',
                'https://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html'
            ]
        }
        for u in p['iam']['credentials']:
            if u['user'] == '<root_account>':
                evidence = {
                    'key'   : '1',
                    'access_key_1_last_rotated' : u['access_key_1_last_rotated']
                }
                if u['access_key_1_last_rotated'] == 'N/A':
                    self.finding(policy,1,evidence)
                else:
                    self.finding(policy,0,evidence)

                evidence = {
                    'key'   : '2',
                    'access_key_1_last_rotated' : u['access_key_1_last_rotated']
                }
                if u['access_key_2_last_rotated'] == 'N/A':
                    self.finding(policy,1,evidence)
                else:
                    self.finding(policy,0,evidence)

        # ------------------------------------------------------
        policy = {
            'name' : 'Ensure MFA is enabled for the "root" account',
            'description' : 'The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html">root user</a> is the highest privileged, unrestricted account within your AWS landscape.  It has to be securely protected.',
            'vulnerability' : 'MFA (or <a href="https://en.wikipedia.org/wiki/Multi-factor_authentication">multi factor authentication</a>) refers to using an additional factor (like a security fob or a one-time password), in addition to the regular username and password to gain access to an account.  This reduces the likelihood of the account being compromised due to the loss of the root username and password.',
            'remediation' : 'Follow the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa">AWS best practices</a> to configure MFA on your root account.',
            'links' : [
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html#enable-virt-mfa-for-root',
                'https://aws.amazon.com/premiumsupport/technology/trusted-advisor/best-practice-checklist/#Security'
            ],
            'references' : [
                'AWS CIS v.1.2.0 - 1.13',
                'Trusted Advisor - Multi-factor authentication on root account'
            ]
        }
        for u in p['iam']['credentials']:
            if u['user'] == '<root_account>':
                if u['mfa_active'] == 'true':
                    self.finding(policy,1)
                else:
                    self.finding(policy,0)

        # ------------------------------------------------------
        policy = {
            'name' : 'Ensure hardware MFA is enabled for the "root" account',
            'description' : 'Protecting the root account with a hardware MFA token to increase security with protecting the credentials.',
            'vulnerability' : 'MFA (or <a href="https://en.wikipedia.org/wiki/Multi-factor_authentication">multi factor authentication</a>) refers to using an additional factor (like a security fob or a one-time password), in addition to the regular username and password to gain access to an account.  This reduces the likelihood of the account being compromised due to the loss of the root username and password.',
            'remediation' : 'Follow the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa">AWS best practices</a> to configure MFA on your root account.',
            'references' : [
                'AWS CIS v.1.2.0 - 1.14'
            ],
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=38'
            ]
        }
        evidence = {
            '<root_account>' : p['iam']['get_account_summary']['AccountMFAEnabled']
        }
        if p['iam']['get_account_summary']['AccountMFAEnabled'] == 1:
            self.finding(policy,1,evidence)
        else:
            self.finding(policy,0,evidence)

        # ------------------------------------------------------
        policy = {
            'name' : 'Ensure IAM policies are attached only to groups or roles',
            'description' : 'Controlling access for users should be done through groups.',
            'vulnerability' : 'Attaching policies directly to user accounts will obfuscate the access a user will have, and can result in permission creep.',
            'remediation' : 'Create IAM groups for each job function, and <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_manage_add-remove-users.html">add the users to the groups</a>.',

            'references' : [
                'AWS CIS v.1.2.0 - 1.16'
            ],
            'links' : [
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_manage_add-remove-users.html',
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=43'
            ]
        }
        for u in p['iam']['credentials']:
            if u['user'] != '<root_account>':
                
                evidence = {
                    u['user'] : {
                        'list_user_policies' : p['iam']['list_user_policies'].get(u['user']),
                        'list_attached_user_policies' : p['iam']['list_attached_user_policies'][u['user']]
                    }
                }
                if len(p['iam']['list_user_policies'].get(u['user'],[])) + len(p['iam']['list_attached_user_policies'].get(u['user'],[])) == 0:
                    self.finding(policy,1,evidence)
                else:
                    self.finding(policy,0,evidence)

        # ------------------------------------------------------
        policy = {
            'name' : 'Ensure IAM instance roles are used for AWS resource access from instances',
            'description' : 'AWS IAM roles reduce the risks associated with sharing and rotating credentials that can be used outside of AWS itself. If credentials are compromised, they can be used from outside of the AWS account they give access to. In contrast, in order to leverage role permissions an attacker would need to gain and maintain access to a specific instance to use the privileges associated with it.',
            'vulnerability' : 'AWS access from within AWS instances can be done by either encoding AWS keys into AWS API calls or by assigning the instance to a role which has an appropriate permissions policy for the required access. "AWS Access" means accessing the APIs of AWS in order to access AWS resources or manage AWS account resources.',
            'remediation' : 'Remove the access keys from any user account in use on an EC2 instance, and setup EC2 IAM Roles instead.',
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=49',
                'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html'
            ],
            'references' : [
                'AWS CIS v.1.2.0 - 1.19'
            ]
        }
        
        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            for ec2 in self.cache['ec2']['describe_instances'][region]:
                compliance = 0
                evidence = {region : ec2['InstanceId']}
                for ia in self.cache['ec2']['describe_iam_instance_profile_associations'][region]:
                    if ia['InstanceId'] == ec2['InstanceId'] and ia['State'] == 'associated':
                        compliance = 1   
                self.finding(policy,compliance,evidence)
        # ------------------------------------------------------
        policy = {
            'name'  : 'Ensure a support role has been created to manage incidents with AWS Support',
            'description' : 'The AWS Support Role allows a user to create and manage support cases with AWS.',
            'vulnerability' : 'Without a support role, no one (with the exception of the root user) will be able to open a support case with AWS.  Note that there are charges for using the support service from AWS.  Refer to their <a href="https://aws.amazon.com/premiumsupport/pricing/">support pricing model</a> for more information.',
            'remediation' : 'Assign the policy AWSSupportAccess to a user or a group.',
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=52',
                'https://aws.amazon.com/premiumsupport/pricing/',
                'https://docs.aws.amazon.com/awssupport/latest/user/getting-started.html',
                'https://docs.aws.amazon.com/awssupport/latest/user/accessing-support.html#iam'
            ],
            'references' : [
                'AWS CIS v.1.2.0 - 1.20'
            ]
        }

        # -- cycle through all the users
        compliance = 0
        evidence = []
        for u in p['iam']['credentials']:
            if u['user'] != '<root_account>':
                # -- check the user's attached policies
                for aup in self.cache['iam']['list_attached_user_policies'][u['user']]:
                    if aup['PolicyArn'] == 'arn:aws:iam::aws:policy/AWSSupportAccess':
                        evidence.append({'user' : u['user']})
                        compliance = 1

                # -- check the user's groups
                for aad in self.cache['iam']['get_account_authorization_details']['UserDetailList']:
                    if aad['UserName'] == u['user']:
                        for g in aad['GroupList']:
                            for agp in self.cache['iam']['list_attached_group_policies'][g]:
                                if agp['PolicyArn'] == 'arn:aws:iam::aws:policy/AWSSupportAccess':
                                    compliance = 1
                                    evidence.append({ 'user' : u['user'], 'group' : g})

                # -- check the role
                for aad in self.cache['iam']['get_account_authorization_details']['RoleDetailList']:
                    for amp in aad['AttachedManagedPolicies']:
                        if amp['PolicyArn'] == 'arn:aws:iam::aws:policy/AWSSupportAccess':
                            evidence.append({'role' : aad['RoleName']})

                            compliance = 1

        self.finding(policy,compliance,evidence)
        # ------------------------------------------------------
        policy = {
            'name'  : 'Do not setup access keys during initial user setup for all IAM users that have a console password',
            'description' : 'IAM users can have multiple credentials, for example passwords, or access keys.',
            'vulnerability' : 'Access to the AWS account needs to be restricted to avoid the account being compromised.  While having an access key is not strictly an issue, having access keys, and a console password would raise concerns on the multiple ways a user can gain access to the system, resulting in a potential breach if the credentials are not properly managed.  <b>Note</b> that while AWS CIS v.1.20 is specifically checking access keys created with user created, AWS Security Info will check for any console user that also has access keys.',
            'remediation' : 'To remediate this issue, either remove the console password, or remove the access keys.',
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=54'
            ],
            'references' : [
                'AWS CIS v.1.2.0 - 1.21'
            ]
        }
        for u in p['iam']['credentials']:
            if u['user'] != '<root_account>':
                evidence = {
                    'user'                          : u['user'],
                    'password_enabled'              : u['password_enabled'],
                    'access_key_1_active'           : u['access_key_1_active'],
                    'access_key_1_last_used_date'   : u['access_key_1_last_used_date'],
                    'access_key_2_active'           : u['access_key_2_active'],
                    'access_key_2_last_used_date'   : u['access_key_2_last_used_date']
                }

                if u['password_enabled'] == 'true' and (u['access_key_1_active'] == 'true' or u['access_key_2_active'] == 'true'):
                    self.finding(policy,0,evidence)
                else:
                    self.finding(policy,1,evidence)
                    

        # ------------------------------------------------------
        policy = {
            'name' : 'Ensure IAM policies that allow full "*:*" administrative privileges are not created',
            'description' : 'Policies define the list of actions that is allowed against a set of resources.  They typically represent all the actions an entity can take as part of a required job function.',
            'vulnerability' : 'Creating an additional policy with administrative access to the entire AWS account has a risk of going undetected, if it is were to be added to a rogue account, leading to a compromise of the AWS account.',
            'remediation' : 'Remove the offending policy, and add the user, group, or role to the AWS managed Administrator policy',
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=57'
            ],
            'references' : [
                'AWS CIS v.1.2.0 - 1.22'
            ]
        }
        evidence = {}
        compliance = 1  # in this case we assume everything is fine, until we find something that is not
        for gpv in self.cache['iam']['get_policy_version']:
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

        self.finding(policy,compliance,evidence)

        # ------------------------------------------------------
        policy = {
            'name' : 'Ensure CloudTrail is enabled in all regions',
            'description' : 'The AWS API call history produced by CloudTrail enables security analysis, resource change tracking, and compliance auditing.',
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html">AWS Best Practices</a> to create a new trail.',
            'vulnerability' : 'Without proper logging of AWS API activity, any activity, be it malicious, or legitimate will go undetected, resulting in breaches, or lack of regulatory compliance.',
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=61',
                'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html',
                'https://aws.amazon.com/premiumsupport/technology/trusted-advisor/best-practice-checklist/#Security'
            ],
            'references' : [
                'AWS CIS v.1.2.0 - 2.1',
                'Trusted Advisor - AWS Cloudtrail logging'
            ]
        }

        IsMultiRegionTrail = False
        IsLogging = False
        IncludeManagementEvents = False
        ReadWriteType = False

        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:            
            for ct in self.cache['cloudtrail']['describe_trails'][region]:
                # IsMultiRegionTrail
                if ct['IsMultiRegionTrail']:
                    IsMultiRegionTrail = True

                if ct['get_trail_status']['IsLogging'] == True:
                    IsLogging = True
                
                for e in ct['get_event_selectors']['EventSelectors']:
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
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html">AWS Best Practices</a> to enable log file validation.',
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=64',
                'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html'
            ],
            'references' : [
                'AWS CIS v.2.2'
            ]
        }

        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            for ct in self.cache['cloudtrail']['describe_trails'][region]:
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
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html">AWS Best practices</a> to configure CloudTrail S3 buckets.',
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=66',
                'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html'
            ],
            'references' : [
                'AWS CIS v.2.3'
            ]
        }
        

        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            for ct in self.cache['cloudtrail']['describe_trails'][region]:

                evidence = { 'region' : region }
                if not 'S3BucketName' in ct:
                    compliance = False
                    evidence['S3BucketName'] = '** No bucket defined ** '
                else:
                    S3BucketName = ct.get('S3BucketName')
                    evidence['S3BucketName'] = S3BucketName
                    evidence['Is_Bucket_Public'] = self.cache['awssecurityinfo']['s3_public_buckets'][S3BucketName]
                
                    if self.cache['awssecurityinfo']['s3_public_buckets'][S3BucketName] == False:
                        compliance = True
                
                self.finding(policy,compliance,evidence)

        # --------------------------------------------------------

        policy = {
            'name' : 'Ensure CloudTrail trails are integrated with CloudWatch Logs',
            'description' : 'Sending CloudTrail logs to CloudWatch Logs will facilitate real-time and historic activity logging based on user, API, resource, and IP address, and provides opportunity to establish alarms and notifications for anomalous or sensitivity account activity.',
            'vulnerability' : 'Without sending CloudTrail logs to CloudWatch, real-time alerts will not be visible, and may go undetected',
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html">AWS Best practices</a> to configure CloudTrail to CloudWatch integration.',
            'reference' : [
                'AWS CIS v.1.2.0 - 2.4'
            ],
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=69',
                'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html'
            ]
        }
        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            evidence = {region: 'none detected'}
            compliance = 0
            for ct in self.cache['cloudtrail']['describe_trails'][region]:
                if 'LatestCloudWatchLogsDeliveryTime' in ct['get_trail_status']:
                    if isinstance(ct['get_trail_status']['LatestCloudWatchLogsDeliveryTime'], (dt.date,dt.datetime)):
                        x =  ct['get_trail_status']['LatestCloudWatchLogsDeliveryTime'].timestamp()
                    else:
                        x =  ct['get_trail_status']['LatestCloudWatchLogsDeliveryTime']

                    if (time.time() - x) < 86400:
                        evidence = {region : ct['get_trail_status']['LatestCloudWatchLogsDeliveryTime']}
                        compliance = 1
                
            self.finding(policy,compliance,evidence)

        

        # --------------------------------------------------------
        policy = {
            'name' : 'Ensure AWS Config is enabled in all regions',
            'description' : 'The AWS configuration item history captured by AWS Config enables security analysis, resource change tracking, and compliance auditing.',
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html">AWS Best Practices</a> to enable AWS Config in all regions.',
            'vulnerability' : 'Without AWS Config enabled, technical teams will struggle to identify the historical changes to resources when the need arise for forensic investigation.',
            'reference' : [
                'AWS CIS v.1.2.0 - 2.5'
            ],
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=72',
                'https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html'
            ]
        }
        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            compliance = 0
            evidence = {'region' : region}
            for c in self.cache['config']['describe_configuration_recorders'][region]:
                if c.get('recordingGroup').get('allSupported') == True and c.get('recordingGroup').get('includeGlobalResourceTypes') == True:
                    # == so far so good.  Let's see if we can find the recording status
                    for s in self.cache['config']['describe_configuration_recorder_status'][region]:
                        if s['name'] == c['name']:
                            if s['recording'] == True and s['lastStatus'] == 'SUCCESS':
                                compliance = 1
            self.finding(policy,compliance,evidence)

        # -------------------------------------------------------
        policy = {
            'name' : 'Ensure rotation for customer created CMKs is enabled',
            'references' : [
                'AWS CIS v.1.2.0 - 2.8'
            ],
            'description' : 'Rotating encryption keys helps reduce the potential impact of a compromised key as data encrypted with a new key cannot be accessed with a previous key that may have been exposed.',
            'vulnerability' : 'By not rotating encryption keys, there is a higher likelihood of data compromize due to improper management of secret keys.',
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html">AWS Best Practices</a> to rotate keys.',
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=82',
                'https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html'
            ]
        }
        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            for k in self.cache['kms']['get_key_rotation_status'][region]:
                evidence = { region : k}

                if self.cache['kms']['get_key_rotation_status'][region][k] == True:
                    self.finding(policy,1,evidence)
                else:
                    self.finding(policy,0,evidence)

        # -------------------------------------------------------
        policy = {
            'name' : 'Ensure VPC flow logging is enabled in all VPCs',
            'description' : 'VPC Flow Logs provide visibility into network traffic that traverses the VPC and can be used to detect anomalous traffic or insight during security workflows.',
            'vulnerability' : 'Without VPC Flow Logs, technical teams will not have visibility on how network traffic flows.',
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html">AWS Best Practices</a> to enable VPC Flow Logs.',
            'reference' : [
                'AWS CIS v.1.2.0 - 2.9'
            ],
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=84',
                'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'
            ]
        }

        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            for v in self.cache['ec2']['describe_vpcs'][region]:
                compliance = 0
                evidence = { region : v['VpcId'] }
                for fl in self.cache['ec2']['describe_flow_logs'][region]:
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
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=88'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.1'
                ],
                'filterPattern' : '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for Management Console sign-in without MFA',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for console logins that are not protected by multi-factor authentication (MFA).',
                'vulnerability' : 'Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=92'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.2'
                ],
                'filterPattern' : '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for usage of "root" account',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for root login attempts.',
                'vulnerability' : 'Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=96'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.3'
                ],
                'filterPattern' : '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for IAM policy changes',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established changes made to Identity and Access Management (IAM) policies.',
                'vulnerability' : 'Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=100'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.4'
                ],
                'filterPattern' : "{ ($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy) }"
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for IAM policy changes',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to CloudTrail\'s configurations.',
                'vulnerability' : 'Monitoring changes to CloudTrail\'s configuration will help ensure sustained visibility to activities performed in the AWS account.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=104'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.5'
                ],
                'filterPattern' : "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for AWS Management Console authentication failures',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for failed console authentication attempts.',
                'vulnerability' : 'Monitoring failed console logins may decrease lead time to detect an attempt to brute force acredential, which may provide an indicator, such as source IP, that can be used in other event correlation.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=108'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.6'
                ],
                'filterPattern' : "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
            },



            {
                'name' : 'Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs ',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for customer created CMKs which have changed state to disabled or scheduled deletion.',
                'vulnerability' : 'Data encrypted with disabled or deleted keys will no longer be accessible.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=112'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.7'
                ],
                'filterPattern' : "{ ($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }"
            },

            {
                'name' : 'Ensure a log metric filter and alarm exist for S3 bucket policy changes',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for changes to S3 bucket policies.',
                'vulnerability' : 'Monitoring changesto S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=108'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.8'
                ],
                'filterPattern' : "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for AWS Config configuration changes ',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is recommended that a metric filter and alarm be established for detecting changes to CloudTrail\'s configurations.',
                'vulnerability' : 'Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=120'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.9'
                ],
                'filterPattern' : "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }}"
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for security group changes',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Security Groups are a stateful packet filter that controls ingressand egress traffic within a VPC. It is recommended that a metric filter and alarm be established changes to Security Groups.',
                'vulnerability' : 'Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=124'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.10'
                ],
                'filterPattern' : "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. NACLs are used as a stateless packet filter to control ingress and egress traffic for subnets within a VPC. It is recommended that a metric filter and alarm be established for changes made to NACLs.',
                'vulnerability' : 'Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=128'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.11'
                ],
                'filterPattern' : "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for changes to network gateways',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Network gateways are required to send/receive traffic to a destination outside of a VPC. It is recommended that a metric filter and alarm be established for changes to network gateways.',
                'vulnerability' : 'Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=132'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.12'
                ],
                'filterPattern' : "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for route table changes',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. Routing tables are used to route network traffic between subnets and to network gateways. It is recommended that a metric filter and alarm be established for changes to route tables.',
                'vulnerability' : 'Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path.',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=136'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.13'
                ],
                'filterPattern' : "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
            },
            {
                'name' : 'Ensure a log metric filter and alarm exist for VPC changes ',
                'description' : 'Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms. It is possible to have more than 1 VPC within an account, in addition it is also possible to create a peer connection between 2 VPCs enabling network traffic to route between VPCs. It is recommended that a metric filter and alarm be established for changes made to VPCs.',
                'vulnerability' : 'Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact',
                'remediation' : 'Follow the steps in the CIS Benchmark paper',
                'links' : [
                    'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=140'
                ],
                'references' : [
                    'AWS CIS v.1.2.0 - 3.14'
                ],
                'filterPattern' : "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
            }

        ]
        
        for POL in POLICIES:
            compliant = False

            # -- go through all the cloudtrail logs, and look for one that has IsMultiRegionTrail set to true
            for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
                for trail in self.cache['cloudtrail']['describe_trails'][region]:
                    if compliant == False: 
                        # -- only keep searching if it is non-compliant.  We just need a single trail that meets all requirements
                        if trail['IsMultiRegionTrail'] == True:
                            if trail['get_trail_status']['IsLogging'] == True:
                                for e in trail['get_event_selectors']['EventSelectors']:
                                    if e['IncludeManagementEvents'] == True:
                                        if e['ReadWriteType'] == 'All':
                                            for f in self.cache['logs']['describe_metric_filters'][region]:
                                                if f['logGroupName'] in trail['CloudWatchLogsLogGroupArn']:                 
                                                    #if f['filterPattern'] == '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }':
                                                    if f['filterPattern'] == POL['filterPattern']:
                                                        for m in self.cache['cloudwatch']['describe_alarms'][region]:
                                                            if f['filterName'] == m['MetricName']:
                                                                for a in m['AlarmActions']:
                                                                    for t in self.cache['sns']['list_topics'][region]:
                                                                        if t['TopicArn'] == a:
                                                                            compliant = True
            self.finding(POL,compliant,None) 
        
        # --------------------------------------
        policy = {
            'name' : 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22',
            'description' : 'Security groups that are configured to allow port 22 (SSH) from the internet.',
            'vulnerability' : 'Removing unfettered connectivity to remote console services, such as SSH, reduces a server''s exposure to risk',
            'remediation' : 'Restrict the incomping IP ranges of the security groups to a smaller IP range, or alternatively, remove the security group.',
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=144'
            ],
            'references' : [
                'AWS CIS v.1.2.0 - 4.1'
            ]
        }
        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            for s in self.security_groups('IpPermissions',region):
                if (s['FromPort'] >= 22 and s['ToPort'] <= 22) and s['IpRange'] in ('0.0.0.0/0','::/0'):
                    self.finding(policy,0,s)
                else:
                    self.finding(policy,1,s)
        # --------------------------------------
        policy = {
            'name' : 'Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389',
            'description' : 'Security groups that are configured to allow port 3389 (RDP) from the internet.',
            'vulnerability' : 'Removing unfettered connectivity to remote console services, such as RDP, reduces a server''s exposure to risk',
            'remediation' : 'Restrict the incomping IP ranges of the security groups to a smaller IP range, or alternatively, remove the security group.',
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=146'
            ],
            'references' : [
                'AWS CIS v.1.2.0 - 4.2'
            ]
        }
        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            for s in self.security_groups('IpPermissions',region):
                if (s['FromPort'] >= 3389 and s['ToPort'] <= 3389) and s['IpRange'] in ('0.0.0.0/0','::/0'):
                    self.finding(policy,0,s)
                else:
                    self.finding(policy,1,s)

        # -----------------------------
        policy = {
            'name' : 'Ensure the default security group of every VPC restricts all traffic',
            'description' : 'Configuring all VPC default security groups to restrict all traffic will encourage least privilege security group development and mindful placement of AWS resources into security groups which will in-turn reduce the exposure of those resources.',
            'vulnerability' : 'The default security group allows very open permissions, and could inadvertently be applied to a resource, exposing that resource to the internet.',
            'remediation' : 'Remove any rules from the default security group.',
            'references' : [
                'AWS CIS v.1.2.0 - 4.3'
            ],
            'links' : [
                'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf#page=148'
            ]
        }    
        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            compliance = 1
            for s in self.security_groups('IpPermissions',region):
                if s['GroupName'] == 'default':
                    compliance = 0
            for s in self.security_groups('IpPermissionsEgress',region):
                if s['GroupName'] == 'default':
                    compliance = 0

            self.finding(policy,compliance,region)

        # --------------------------------------------------------
        policy = {
            'name' : 'S3 buckets must not be publicly accessible',
            'description' : 'Publically accessible S3 buckets will allow anyone on the internet to access any data stored in a S3 bucket',
            'vulnerability' : 'Misconfigured permissions on the S3 bucket can result in unauthorised data disclosure',
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonS3/latest/user-guide/block-public-access.html">AWS Best Practices</a> to remediate the publically exposed bucket.',
            'reference' : [
                'ASI.DP.001',
                'Trusted Advisor - Amazon S3 bucket permissions'
            ],
            'links' : [
                'https://github.com/massyn/aws-security/blob/main/policies/ASI.DP.001%20-%20S3%20buckets%20must%20not%20be%20publicly%20accessible.md',
                'https://docs.aws.amazon.com/AmazonS3/latest/user-guide/block-public-access.html',
                'https://aws.amazon.com/premiumsupport/technology/trusted-advisor/best-practice-checklist/#Security'
            ]
        }
        for bucket in self.cache['s3']['policy']:
            evidence = []
            compliance = 1
            for s in self.cache['s3']['policy'][bucket].get('Statement',[]):
                for Effect in self.lister(s['Effect']):
                    for Principal in self.lister(s['Principal']):
                        #for Action in self.lister(s['Action']):
                            #for Resource in self.lister(s['Resource']):
                                # 5 
                        if Effect == 'Allow' and Principal == {'AWS' : '*'} or Principal == '*':
                            evidence.append({bucket : self.cache['s3']['policy'][bucket].get('Statement',[]) })
                            compliance = 0
                                
            #for acl in self.cache['s3']['bucketacl'][bucket]:
            for g in self.cache['s3']['bucketacl'][bucket]['grants']:
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
            'references' : [
                'ASI.DP.2'
            ],
            'links' : [
                'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html'
            ]
        }
        
        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            compliance = 0
            if len(self.cache['guardduty']['list_detectors'][region]) > 0:
                compliance = 1
            else:
                compliance = 0
                
            self.finding(policy,compliance,region)

        # --------------------------------------------------------
        policy = {
            'name' : 'IAM Roles with Admin Rights',
            'description' : 'IAM roles should have least privilege defined in its execution role, and only be able to perform very specific tasks.',
            'vulnerability' : 'If a role with high level access is compromised, it has the potential to cause severe business disruption to the AWS account.',
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html">AWS Best Practices</a> to restrict the roles.',
            'references' : [
                'ASI.IAM.001'
            ],
            'links' : [
                'https://github.com/massyn/aws-security/blob/main/policies/ASI.IAM.001%20-%20IAM%20Roles%20with%20Admin%20Rights.md'
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html',
                'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html'
            ]
        }
        
        for list_roles in self.cache['iam']['list_roles']:
            compliance = 1
            for q in self.parsePermissions():
                if 'RoleName' in q:
                    if q['RoleName'] == list_roles['RoleName'] and q['Effect'] == 'Allow' and q['Action'] == '*' and q['Resource'] == '*':
                        compliance = 0
                                        
            self.finding(policy,compliance,list_roles['RoleName'])

        # --------------------------------------------------------
 
        policy = {
            'name' : 'Subnets should not issue public IP addresses',
            'description' : 'To improve the security of VPCs, it is recommended that subnets should not allocate public IP addresses.',
            'vulnerability' : 'Automated issuing of public IP addresses increases the risk of internet exposure to your instances.',
            'remediation' : 'Execute the <a href="https://github.com/massyn/aws-security/blob/main/remediation/remediate_subnets_with_public_ip_assignment.py">remediation script</a> within your AWS account to remediate all subnets.',
            'references' : [
                'ASI.NET.001'
            ],
            'links' : [
                'https://github.com/massyn/aws-security/blob/main/policies/ASI.NET.001%20-%20Subnets%20should%20not%20issue%20public%20IP%20addresses.md',
                'https://docs.aws.amazon.com/vpc/latest/userguide/working-with-vpcs.html#AddaSubnet'
            ]
        }
        
        for region in [region['RegionName'] for region in self.cache['ec2']['describe_regions']]:
            for subnet in self.cache['ec2']['describe_subnets'][region]:
                self.finding(policy,subnet['MapPublicIpOnLaunch'] == False,{ 'region' : region, 'SubnetId' : subnet['SubnetId']})
            # --------------------------------------------------------
        


    # ======================================================================================
    def parsePermissions(self):
        """
        parsePermissions will read all permissions for users and roles, and print out the individual policy permissions they have

        """
        perm = []

        # == cycle through all users ==
        for u in self.cache['iam']['list_users']:
            UserName = u['UserName']

            # -- find all inline policies
            if UserName in self.cache['iam']['list_user_policies']:
                for PolicyName in self.cache['iam']['list_user_policies'][UserName]:

                    for q in self.flattenStatements(self.cache['iam']['list_user_policies'][UserName][PolicyName]['Statement']):
                        q['source'] = 'list_user_policies'
                        q['UserName'] = UserName
                        q['PolicyName'] = PolicyName
                        q['Entity'] = u['Arn']
                        perm.append(q)

            # -- find all policies attached
            for p in self.cache['iam']['list_attached_user_policies'][UserName]:
                PolicyName = p['PolicyName']
                poly = self.cache['iam']['get_policy_version'][PolicyName]
                for q in self.flattenStatements(poly['Document']['Statement']):
                    q['source'] = 'list_attached_user_policies'
                    q['UserName'] = UserName
                    q['PolicyName'] = PolicyName
                    q['Entity'] = u['Arn']
                    perm.append(q)

            # -- find all groups
            for GroupName in self.cache['iam']['get_group']:
                for g in self.cache['iam']['get_group'][GroupName]['Users']:
                    if UserName == g['UserName']:
                        # -- find all policies attached to the groups
                        for p in self.cache['iam']['list_attached_group_policies'][GroupName]:
                            PolicyName = p['PolicyName']
                            poly = self.cache['iam']['get_policy_version'][PolicyName]
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
                                for q in self.flattenStatements(self.cache['iam']['list_group_policies'][GroupName][PolicyName]['Statement']):
                                    q['source'] = 'list_group_policies'
                                    q['GroupName'] = GroupName
                                    q['UserName'] = UserName
                                    q['PolicyName'] = PolicyName
                                    q['Entity'] = u['Arn']
                                    perm.append(q)

        # == cycle through all roles
        for r in self.cache['iam']['list_roles']:
            RoleName = r['RoleName']

            # -- find all policies attached to the roles
            for p in self.cache['iam']['list_attached_role_policies'][RoleName]:
                PolicyName = p['PolicyName']

                poly = self.cache['iam']['get_policy_version'][PolicyName]
                for q in self.flattenStatements(poly['Document']['Statement']):
                    q['source'] = 'list_attached_role_policies'
                    q['RoleName'] = RoleName
                    q['PolicyName'] = PolicyName
                    q['Entity'] = r['Arn']
                    perm.append(q)
            # -- do roles have inline policies?
            if RoleName in self.cache['iam']['list_role_policies']:
                for PolicyName in self.cache['iam']['list_role_policies'][RoleName]:
                    
                    for q in self.flattenStatements(self.cache['iam']['list_role_policies'][RoleName][PolicyName]['Statement']):
                        q['source'] = 'list_role_policies'
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


    