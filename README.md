# aws-security
Scan your own AWS account for security vulnerabilities
## Getting started
### Installing Python libraries
aws-security has been built with Python 3.9.  Install the requred libraries.
```
pip install -r requirements.txt
```
### AWS Account
The script needs an IAM account, or at least some credentials to query the AWS account.  At the very least, the script must have read-only access.
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html

### S3 bucket
You can store your data files on the local machine, but it makes more sense to use an S3 bucket.  It is recomended that you create an S3 bucket to store all data files.

### Slack
The solution has built in support for Slack.  You can provide a Slack Webhook to receive alerts directly in your channel for any issues that have been identified.

## Running a security scan
### Option 1 - Use CloudShell
This method requires an S3 bucket to be created.

* Open a CloudShell session - https://console.aws.amazon.com/cloudshell/home?region=us-east-1
* Execute the following commands
```
$ cd /tmp
$ git clone https://github.com/massyn/aws-security
$ cd aws-security/
$ python3 scanner/scanner.py --json "s3://BUCKET NAME/%%a-%%d.json" --html "s3://BUCKET NAME/%%a-%%d.html"
```
* Once the signed URL is generated, you can download the generated report.

### Option 2 - Use built-in credentials
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html

```
$ python3 scanner/scanner.py --json tmp/site.json --html tmp/report.html
```

### Option 3 - Use access keys
```
$ python3 scanner/scanner.py --json tmp/site.json --html tmp/report.html --aws_access_key_id _access key_ --aws_secret_access_key _secret_access_key_
```
### Option 4 - Assume role
You can use Assume Role to scan another AWS account, assuming the target account has granted you access to assume the role.


```
$ python3 scanner/scanner.py --json tmp/site.json --html tmp/report.html --assumerole _ROLENAME_ --account _target AWS account ID_ --externalid _EXTERNALID_
```
You can [deploy](cloudformation/readonly.json) the read-only stackset on the target account.  Change the account and external ID to your source detail (leaving the details as is will grant my account access to your AWS account.)
```
$ python3 scanner/scanner.py --json tmp/site.json --html tmp/report.html --assumerole AWSSecurityInfoReadOnlyRole --account _target AWS account ID_ --externalid 717CF4D0BF1E46C3CD59B0B8BF85D11314896814C522CE67D59CBE6F58DA1866
```

### Option 5 - Lambda
You have the option to run the code inside a Lambda function.  *There is a known issue where Lambda can only offer a 15 minute execution time.  The current script may run more than 30 minutes, so it is unlikely it will complete on time.*

* Create a role in IAM with the necessary permissions (TODO)
* Create an S3 bucket and allow the Lambda function PutObject and GetObject access
* Create a lambda function, using Python 3.8 as the code base
* Copy all the files in the "scanner" directory to be used by the python function
* Be sure to rename scanner.py to lambda_function.py
* Create an environment variable called S3_BUCKET and put the s3 bucket name in there
* If you want to use slack for notifications, create an environment variable called SLACK_WEBHOOK and place the webhook url in there

You can invoke the Lambda function.  You basically have 3 choices :

* Run it with no payload will execute against the account it runs in.
* Run it with a simple payload of accountId and externalId where you specify the target account Id and the external Id.  The function will attempt to switch the role, and run the process.
```
{
    "accountId" : "123456789012",
    "externalId" : "yourVerySecretExternalId"
}
```
* You can also put the payload in an array, which will invoke individual Lambda functions
```
[
    {
        "accountId" : "123456789012",
        "externalId" : "yourVerySecretExternalId"
    },
    {
        "accountId" : "098765432109",
        "externalId" : "yourVerySecretExternalId"
    }
]
```

## About the policies
There are a number of policies built into the script. The open format will also allow you to build your own policies.  The policies are in two distinct categories.

The first is the _industry best practice_ category, and this is typically policies that relate to the Center for Internet Security, or PCI standards.  These policies will be as true to the industry standard as possible, and will not be modified.

The second catory is _AWS Security Info Specific_, and there I am more than happy to entertain changes and tweaks to the policy.  

## How to submit a change request
Simply open an issue in [Github](https://github.com/massyn/aws-security/issues), and I'll review the request and include it into the solution.  You're also welcome to fork the solution, and submit a pull request to merge your own policies into the solution.
