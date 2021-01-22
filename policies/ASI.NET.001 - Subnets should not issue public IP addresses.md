# Subnets should not issue public IP addresses

## Why is this a problem?
Defence-in-depth suggests that multiple security controls must be implemented to properly protect a system.  Removing the assignment of public IP addresses is one strategy that can be deployed to reduce the risk.

By allocating public IP addresses in subnets, any new system being created (database or EC2 instance) could inadvertantly be exposed to the public internet.

Instead of simply giving EC2 instances public IP addresses, the solution must be designed in a way to utilize load balancers instead.  Note that the subnet where you place a load balancer will need to have the ability to issue public IP addresses. Consider creating a load balancer with a public IP before you remove the functionality.

## What can you do about it?
Log onto the AWS Console, navigate to the VPC, select the subnet, and remove the ability to issue a public IP address.

## Remediation ##
Execute [remediate_subnets_with_public_ip_assignment.py](https://github.com/massyn/aws-security/blob/main/remediation/remediate_subnets_with_public_ip_assignment.py) against the AWS account.
:warning: **WARNING**: The script will cause all subnets in all regions to stop issuing public IP addresses.  If you need this functionality for things like autoscaling, this script can potentially break your solution.:warning:
## References
* ASI.NET.001