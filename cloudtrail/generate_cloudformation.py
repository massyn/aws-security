import json
import os
import boto3

def ZipFile():
    with open('lambda.py','rt') as f:
        result = ''
        for l in f.readlines():
            l = l.replace('\n','')
            if l != '':
                result += l + '\n'
    return result

def main():
    Z = ZipFile()
    template = {
        "AWSTemplateFormatVersion" : "2010-09-09",
        "Description" : "Monitor CloudTrail in real-time, and send alerts to Slack",
        "Parameters": {
           "SLACKWEBHOOK": {
              "Description" : "URL of the Slack Webhook",
              "Type": "String"
            }
        },
        "Resources": {
            "LambdaExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName" : { "Fn::Sub": "${AWS::StackName}-Role-CloudTrail2Slack" },
                    "Path": "/",
                    "Policies": [ {
                        "PolicyName": "CloudwatchLogs",
                        "PolicyDocument": {
                            "Statement": [ {
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:GetLogEvents",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": [ "arn:aws:logs:*:*:*" ],
                                "Effect": "Allow"
                            }]
                        }
                    }],
                    "AssumeRolePolicyDocument": {
                        "Statement": [{
                            "Action": [ "sts:AssumeRole" ],
                            "Effect": "Allow",
                            "Principal": { "Service": [ "lambda.amazonaws.com" ] }
                        }]
                    }
                }
            },
            "LambdaFunction":{
                "Type" : "AWS::Lambda::Function",
                "Properties" : {
                    "Code": { "ZipFile": Z },
                    "Description" : "Send a message to Slack",
                    "Environment" : { "Variables" : { "SLACK_WEBHOOK" : {"Ref" : "SLACKWEBHOOK"} }},
                    "FunctionName": { "Fn::Sub": "${AWS::StackName}-Lambda-CloudTrail2Slack" },
                    "Handler" : "index.handler",
                    "MemorySize" : 128,
                    "Role": { "Fn::GetAtt": [ "LambdaExecutionRole", "Arn" ] },
                    "Runtime" : "python3.8",
                    "Timeout" : 3
                },
                "DependsOn": [ "LambdaExecutionRole" ]
            }   
        }
    }

    dir = 'eventPatterns'
    for f in os.listdir(dir):
        print(' -- ' + f)
        Description = f.replace('_',' ').replace('.json','')
        key = f.replace('_','').replace('.json','').replace(' ','').replace('.','')
        with open(dir + '/' + f ,'rt') as f:
            data = json.load(f)

        template["Resources"]["Rule" + key] = {
            "Type": "AWS::Events::Rule",
            "Properties": {
                "Description": Description,
                "EventPattern":  data['EventPattern'],
                "Name": { "Fn::Sub": "${AWS::StackName}-Rule-" + key  },
                "State": "ENABLED",
                "Targets": [{ 
                    "Arn": { "Fn::GetAtt": [ "LambdaFunction", "Arn" ] },
                    "Id" : { "Fn::Sub": "${AWS::StackName}-LambdaFunction" } ,
                    "InputTransformer" : {
                        "InputPathsMap" : data['InputPathsMap'],
                        "InputTemplate" : data['InputTemplate']
                    }

                } ]
            }
        }
            
        template["Resources"]["PermissionForEventsToInvokeLambda" + key] = {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "FunctionName": { "Ref": "LambdaFunction" },
                "Action": "lambda:InvokeFunction",
                "Principal": "events.amazonaws.com",
                "SourceArn": { "Fn::GetAtt": ["Rule" + key , "Arn"] }
            }
        }
    
    tmpfile = 'c:/temp/cf.json'
    with open(tmpfile,'wt') as f:
        f.write(json.dumps(template,indent=4))
        f.close()
    
    BUCKET = 'awssecurityinfo-resources'
    #FILE = 'cloudtrail-slack.json'
    FILE = 'cloudtrail-slack-TEST.json'
    s3 = boto3.resource('s3')
    print('Uploading to S3...')
    s3.meta.client.upload_file(tmpfile, BUCKET, FILE)
    print('-----------------------')
    print('https://{BUCKET}.s3.ap-southeast-2.amazonaws.com/{FILE}'.format(BUCKET = BUCKET, FILE = FILE))

main()
