import boto3

# Enable VPC Flow Logs on all regions with a 30 day retention policy

def create_flowlogs_policy(ACCESS_KEY,SECRET_KEY,SESSION_TOKEN,policyName):
    iam = boto3.client('iam',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        aws_session_token=SESSION_TOKEN
    )

    # does the policy exist ?
    arn = ''
    for p in iam.list_policies()['Policies']:
        if p['PolicyName'] == policyName:
            arn = p['Arn']

    if arn == '':
        print ('- Creating policy ' + str(policyName))
        response = iam.create_policy(
            PolicyName = policyName,
            PolicyDocument = '''{
                    "Version" : "2012-10-17",
                    "Statement": [
                        {
                            "Action": [
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:DescribeLogGroups",
                                "logs:DescribeLogStreams",
                                "logs:PutLogEvents"
                            ],
                            "Effect": "Allow",
                            "Resource": "*"
                        }
                    ]
            }'''

        )
        arn = response['Policy']['Arn']
    
    print(arn)
    return arn

def create_flowlogs_role(ACCESS_KEY,SECRET_KEY,SESSION_TOKEN,roleName, policyArn):
    iam = boto3.client('iam',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        aws_session_token=SESSION_TOKEN
    )
    arn = ''
    for r in iam.list_roles()['Roles']:
        if r['RoleName'] == roleName:
            arn = r['Arn']

    if arn == '':
        print(' -- creating role ' + roleName)
        x = iam.create_role(
            RoleName = roleName,
            AssumeRolePolicyDocument = '''{
            "Version": "2012-10-17",
            "Statement": [
                {
                "Sid": "",
                "Effect": "Allow",
                "Principal": {
                    "Service": "vpc-flow-logs.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
                }
            ]
            }'''
        )
        arn = x['Role']['Arn']

        print('arn = ' + arn)
        print ('Attaching policy ' + policyArn + ' to role ' + roleName )
        iam = boto3.resource('iam',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN
        )
        role = iam.Role(roleName)
        response = role.attach_policy(
            PolicyArn=policyArn
        )
        print(response)
    return arn

def create_vpc_flowlogs(ACCESS_KEY,SECRET_KEY,SESSION_TOKEN,cw_flowlogs_log_group,roleArn):
    for region in [region['RegionName'] for region in boto3.client('ec2', region_name = 'us-east-1',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN).describe_regions()['Regions']]:
        
        for vpcId in [x['VpcId'] for x in boto3.client('ec2',
            region_name = region,
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN).describe_vpcs()['Vpcs']]:
            print(region + ' - ' + vpcId)

            try:
                x = boto3.client('ec2', region_name = region,
                    aws_access_key_id=ACCESS_KEY,
                    aws_secret_access_key=SECRET_KEY,
                    aws_session_token=SESSION_TOKEN).create_flow_logs(
                        ResourceIds              = [ vpcId ],
                        ResourceType             = 'VPC',
                        TrafficType              = 'ALL',
                        LogGroupName             = cw_flowlogs_log_group,
                        DeliverLogsPermissionArn = roleArn
                    )
                print('  ==> SUCCESS - ' + x['FlowLogIds'])

            except:
                print('  ==> ERROR - it may already exist')

            # == Update the retention policy to 30 days
            response = boto3.client('logs',
                region_name = region,
                aws_access_key_id=ACCESS_KEY,
                aws_secret_access_key=SECRET_KEY,
                aws_session_token=SESSION_TOKEN
            ).put_retention_policy(
                    logGroupName=cw_flowlogs_log_group,
                    retentionInDays=30
            )


# ===== main program =====
def remediate_vpc_flowlogs(a = None,b = None,c = None):
    """
        AWS VPC has flow logs disabled
    """

    policy_arn = create_flowlogs_policy(a,b,c,'flowlogsPolicy')
    roleArn = create_flowlogs_role(a,b,c,'flowlogsRole',policy_arn)
    create_vpc_flowlogs(a,b,c,'flowlogs',roleArn)

remediate_vpc_flowlogs()
