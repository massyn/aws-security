
# CloudTrail to Slack alerting

## Prerequisits
* [CloudTrail must be enabled](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html)
* [CloudWatch Integration has to be enabled](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html)

## Create Cloudformation Stack
You can [Launch a Stack](https://console.aws.amazon.com/cloudformation/home?#/stacks/new?stackName=CloudTrail2Slack&templateURL=https://awssecurityinfo-resources.s3.ap-southeast-2.amazonaws.com/cloudtrail-slack.json) here, or install the latest CloudFormation from S3 https://awssecurityinfo-resources.s3.ap-southeast-2.amazonaws.com/cloudtrail-slack.json

## How does it work?
The files in this repo are used to geneate a [Cloudformation Template]](https://console.aws.amazon.com/cloudformation/home?#/stacks/new?stackName=CloudTrail2Slack&templateURL=https://awssecurityinfo-resources.s3.ap-southeast-2.amazonaws.com/cloudtrail-slack.json) that is used to build all the resources within your AWS account.
* Rules are created in AWS EventBridge to track specific rules that may occur through CloudTrail
* Eventbridge will trigger a Lambda function
* The Lambda function will send a Slack alert

If you don't like a particular rule, go into EventBrige, and disable it.  Do note that any changes you make will potentially be overwritten when you update the stack.

### How to submit a change request
Do you have an idea for a new use case that should be monitored, or, did you spot an issue?  Simply open an issue in [Github](https://github.com/massyn/aws-security/issues), and I'll review the request and include it into the solution.  You're also welcome to fork the solution, and submit a pull request to merge your own policies into the solution.