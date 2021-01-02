# S3 buckets must not be publicly accessible

[S3](https://aws.amazon.com/s3/) is a core storage solution from AWS.  It is used in most services, and provides an secure and scalable storage solution for your application.  If configured correctly, S3 can host highly sensitive information.

This check is also available through [AWS Trusted Advisor](https://aws.amazon.com/premiumsupport/technology/trusted-advisor/best-practice-checklist/).

## Why is this a problem?
### Confidentiality
* Data within the bucket could be exposed, resulting in a loss of confidentiality.
* When other files (for example web site images) are stored, there is a risk that another website may be using your resources by linking to the public bucket, incurring additional charges to your account.

### Integrity
* An attacker may be able to modify sensitive data (for example updating an invoice to be paid with new bank details)
* An attacker may be able to inject their own data into the bucket (for example submitting a fake order through an EDI system)

### Availability
* An attacker may be able to delete sensitive data, resulting in a system outage.

## What can you do about it?
Limit the bucket policies to the least privileges required.  Refer to [secure-s3-resources](https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/) for more details.
## Remediation ##
### cli
```
aws s3 delete-bucket-policy --bucket BUCKET_NAME
```
### Python
```
import boto 3
s3 = boto3.client('s3')
s3.delete_bucket_policy(Bucket='BUCKET_NAME')
```
## Additional information
* https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/
* https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html

## References
* ASI.DP.001
* [Trusted Advisor](https://aws.amazon.com/premiumsupport/technology/trusted-advisor/best-practice-checklist/) -  Amazon S3 bucket permissions (free)
