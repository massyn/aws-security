# aws-security
Scan your own AWS account for security vulnerabilities
## Getting started
### Installing Python libraries
aws-security has been built with Python 3.8.  Install the requred libraries.
```
pip install -r requirements.txt
```
### AWS Account
The script needs an IAM account, or at least some credentials to query the AWS account.  At the very least, the script must have read-only access.
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html

## Running a security scan
### Option 1 - Use CloudShell
This method requires an S3 bucket to be created.

* Open a CloudShell session - https://console.aws.amazon.com/cloudshell/home?region=us-east-1
* Execute the following commands
```
$ cd /tmp
$ git clone https://github.com/massyn/aws-security
$ cd aws-security/
$ python scanner/scanner.py --oh "s3://BUCKET NAME/%%a-%%d.html"
```
* Once the signed URL is generated, you can download the generated report.

### Option 2 - Use built-in credentials
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html

```
python scanner\scanner.py --json tmp\site.json --oh tmp\report.html
```

### Option 3 - Use access keys

### Option 4 - Assume role

### Option 5 - Lambda
You have the option to run the code inside a Lambda function.

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

