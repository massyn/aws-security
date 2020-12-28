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
                        'list_user_policies' : p['iam']['list_user_policies'][u['user']],
                        'list_attached_user_policies' : p['iam']['list_attached_user_policies'][u['user']]
                    }
                }
                if len(p['iam']['list_user_policies'][u['user']]) + len(p['iam']['list_attached_user_policies'][u['user']]) == 0:
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
                    if self.comparer(s['Effect'],'Allow') and self.comparer(s['Action'],'*') and self.comparer(s['Resource'],'*'):
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
            'name' : 'S3 buckets are not publicly accessible',
            'description' : 'Publically accessible S3 buckets will allow anyone on the internet to access any data stored in a S3 bucket',
            'vulnerability' : 'Misconfigured permissions on the S3 bucket can result in unauthorised data disclosure',
            'remediation' : 'Follow <a href="https://docs.aws.amazon.com/AmazonS3/latest/user-guide/block-public-access.html">AWS Best Practices</a> to remediate the publically exposed bucket.',
            'reference' : [
                'ASI.DP.1',
                'Trusted Advisor - Amazon S3 bucket permissions'
            ],
            'links' : [
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
                                
            for acl in self.cache['s3']['bucketacl'][bucket]:
                for g in self.cache['s3']['bucketacl'][bucket]['grants']:
                    if g['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' or g['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/Authenticated Users':
                        compliance = 0
                        evidence.append({bucket : g })
                        
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
                'AWS CIS v.1.2.0 - 2.9'
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
                    

    # ======================================================================================

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