# IAM Roles with Admin Rights

An [IAM Roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html) can be considered like a user account - it is an entity that can have access to the AWS account, with specific permissions.  If the role has too many permissions, there is a likelihood of compromise of the AWS account.

## Why is this a problem?
When the role is abused, the attacker will be able to execute any command the role has access to.  In this specific use case, the policy is checking for roles that have administrative access.

## What can you do about it?
Administrative policies must not be attached to any role.

## Remediation ##

## Additional information
* https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html

## References
* ASI.IAM.001
