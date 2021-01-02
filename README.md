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
https://console.aws.amazon.com/cloudshell/home?region=us-east-1

```
$ cd /tmp
$ git clone https://github.com/massyn/aws-security
$ cd aws-security/
$ python3 scanner/scanner.py --json site.json --oh report.html
```

### Option 2 - Use built-in credentials
https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html

```
python scanner\scanner.py --json tmp\site.json --oh tmp\report.html
```

### Option 3 - Use access keys

### Option 4 - Assume role

### Option 5 - Lambda

