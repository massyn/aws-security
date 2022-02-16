# Extract all security group rules
import boto3

def extract_security_groups(region_name = None):
    ec2 = boto3.client('ec2',region_name = region_name)

    print('direction;type;GroupId;GroupName;FromPort;ToPort;IpProtocol;range')
    for sg in ec2.describe_security_groups()['SecurityGroups']:
        #print('-------------------------')
        #print(sg)
        for direction in ['IpPermissions','IpPermissionsEgress']:
            for rule in sg[direction]:
                
                
                for IpRanges in rule['IpRanges']:
                    print(f"{direction};CidrIp;{sg['GroupId']};{sg['GroupName']};{rule.get('FromPort','*')};{rule.get('ToPort','*')};{rule['IpProtocol']};{IpRanges['CidrIp']}")

                for Ipv6Ranges in rule['Ipv6Ranges']:
                    print(f"{direction};CidrIpv6;{sg['GroupId']};{sg['GroupName']};{rule.get('FromPort','*')};{rule.get('ToPort','*')};{rule['IpProtocol']};{Ipv6Ranges['CidrIpv6']}")

                for UserIdGroupPairs in rule['UserIdGroupPairs']:
                    print(f"{direction};UserIdGroupPairs;{sg['GroupId']};{sg['GroupName']};{rule.get('FromPort','*')};{rule.get('ToPort','*')};{rule['IpProtocol']};{UserIdGroupPairs.get('GroupId')}")

extract_security_groups('ap-southeast-2')