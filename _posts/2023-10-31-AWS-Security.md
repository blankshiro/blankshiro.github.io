---
layout: post
title: AWS Security
date: 2023-10-31
categories: [Course, AWS Security]
tags: [Course, AWS Security]
---

# AWS Security

## Security Overview

### Security Priorities

-   **Infrastructure security**: firewalls, intrusion detection and prevention systems, and secure data storage.
-   **Operations security**: access control, authentication and authorization.
-   **Applications security**: vulnerability scanning, penetration testing, and code reviews.

### A Well-Architected Framework

-   **Automation**: deploying environments in a secure and reproducible manner.
-   **Visibility**: maintaining a complete inventory of your resources to facilitate compliance auditing and security analysis.
-   **Auditability**: ensuring which actions specific users took over a given time, find source and destination IP etc are being logged.
-   **Agility**: Automatically scaling to provide high availability during a security attack.
-   **Controllability**: Providing methods to control encryption keys and manage access controls for users, group and roles etc.

### Security Core Aspects

-   **Confidentiality**: limiting access and disclosure to authorized users and preventing access by unauthorized people.
-   **Integrity**: maintain data consistency during its lifecycle and preserving data at rest and in transit.
-   **Availability**: readiness of information resources when needed. 

### Threat Modelling

-   Identify assets, actors, entry points, components, use cases, and trust levels, and fill out a data flow table
-   Identify a list of threats
-   Document the potential vulnerabilities.
    -   Vulnerability, threat, mitigation, severity, owner.

>   **Tip**: Leverage on STRIDE Framework or MITRE ATT&CK Framework.

## Access and Authorization on AWS

### Securing APIs through signing

-   **Prevent tampering**: hash value is calculated and used to determined whether the request has been modified in transit.
-   **Prevent reply attacks**: requests are timestamped.

### IAM Roles

-   Used to delegate access to resources and users temporarily instead of sharing credentials.

### IAM Threat: Compromised long-term credentials

##### Solution: AWS Security Token Service

-   Best practice is to use short-term credentials
    -   To eliminate the need to rotate and revoke when they are no longer required
-   AWS STS as a web service that enables you to request temporary, limited-privilege credentials for users.

![AWS STS Example](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/AWS%20Security/STS-Example.png?raw=true)

### IAM Threat: Overly permissive and misconfigured policies

##### Solution: Analyze policies and use least privilege

-   Use IAM roles with session policies
-   Add conditions to constrain role assumption (time of day, resource tag, etc)

##### Types of Policies

-   **Identity-based**: attach managed and inline policies to IAM identities.
-   **Resource-based**: attach inline policies to resources.
-   **Permission boundaries**: defines the max permissions that the identity-based policies can grant to an entity. *Does not grant permissions*.

>   Managed policy is better than inline policy: **control**, **versioning**, **reusability** and **central change management**.
>
>   Implicit permission are always weak because they can be overwritten.
>
>   Best practice is to add an explicit deny at the end of the policy to ensure a safeguard.

### IAM Threat: Anomalous IAM entity behaviour

##### Solution: Ensure threats are identified with security monitoring

-   API logging with CloudTrail

##### CloudTrail Best Practices

-   Send all CloudTrail logs to S3 or CloudTrail Lake for storage and log retention
-   Centralize collecting of logs to a dedicated account/region
-   Enable log file integrity
-   Enforce least privilege principle
-   Enforce MFA delete on the log S3 bucket
-   Activate S3 versioning

### Lab 1: Using Identity and Resource-Based Policies

###### Bucket Policy: `ListAllMyBuckets`

```bash
...
{
  "Action": [
    "s3:ListAllMyBuckets",
    "s3:ListBucket"
  ],
  "Resource": "*",
  "Effect": "Allow"
},
...
```

```bash
sh-4.2$ aws s3 ls
2023-03-03 14:25:31 awslabs-resources-abcdef
2023-10-31 02:14:06 backup-bucket
2023-10-31 02:14:06 data-bucket
sh-4.2$ aws s3 ls $bucketName # to list individual buckets
```

###### Bucket Policy: `PutObject`

```bash
...
{
  "Action": [
    "s3:PutObject"
  ],
  "Resource": [
    "arn:aws:s3:::data-bucket/file1.txt",
    "arn:aws:s3:::data-bucket/file2.txt",
    "arn:aws:s3:::data-bucket/file3.txt",
    "arn:aws:s3:::data-bucket/file4.txt",
    "arn:aws:s3:::backup-bucket/file1.txt",
    "arn:aws:s3:::backup-bucket/file2.txt",
    "arn:aws:s3:::backup-bucket/file3.txt",
    "arn:aws:s3:::backup-bucket/file4.txt"
  ],
  "Effect": "Allow",
  "Sid": "AllowS3PutObjectToLabBuckets"
}
...
```

```bash
sh-4.2$ pwd
/home/ec2-user/lab1
sh-4.2$ ls
file1.txt  file2.txt  file3.txt  file4.txt

# Try putting file into bucket
sh-4.2$ aws s3 cp /home/ec2-user/lab1/file1.txt s3://data-bucket
upload: ./file1.txt to s3://data-bucket/file1.txt
sh-4.2$ aws s3 ls data-bucket
2023-10-31 03:47:30         61 file1.txt

# Try deleting file from bucket
sh-4.2$ aws s3 rm s3://data-bucket/file1.txt
delete failed: s3://data-bucket/file1.txt An error occurred (AccessDenied) when calling the DeleteObject operation: Access Denied
```

## Account Management and Provisioning on AWS

### Managing Multiple AWS accounts

##### Possible Challenges 

-   Sharing an account across different teams can cause conflicts in visibility and accountability. 
-   Security needs can differ across teams or profiles. 
-   Development, staging, and production often require isolation from one another.
-   You might have business units or products that require separate accounts

##### Solution: AWS Organizations

-   Policy-based, central management for multiple AWS account
-   Service Control Policies (SCP)
-   Automated, API-driven account creation
-   Create an organization –> Create OUs –> Add AWS accounts –> Create and assign SCP (policy that specifies the services and actions that users and roles can use)

##### Another solution: AWS Control Tower

-   Automates setup of multiple accounts based on best practices in a landing zone
-   Applies prepackaged controls that provide ongoing governance
-   Provides an integrated dashboard to view controls applied to your environment

>   Choose AWS Organizations if you want to define your own custom multi-account environment with advanced management capabilities
>
>   Choose AWS Control Tower if you want to automate deployment of multi-account environment according to AWS best practices

### Lab 2: Managing Domain User Access with AWS Directory Service

In Windows AD:

-   Create new group name `AWS EC2 read-only` and `AWS S3 read-only`.
-   Add Alice to `AWS EC2 read-only` and Bob to `AWS S3 read-only`.

In AWS Management (Directory Service):

-   Associate directory users with IAM roles.

## Managing Keys and Secrets on AWS

### AWS KMS

-   Managed key storage and management and data encryption
-   Two-tiered key hierarchy using envelope encryption (encrypting plaintext data with a data key, and then encrypting the data key under another key)
-   Centrally managed and secured keys
-   Supports external key store for regulated workloads 
-   Can either manage KMS keys yourself or let AWS create and manage keys

##### Protecting your keys

-   Policies

    -   Offer resource-based permissions
    -   Make it possible to specify who can manage and who can encrypt or decrypt

-   Grants

    -   Offer temporary or more granular permissions
    -   Possible to programmatically delegate customer managed keys
    -   Can be used to permit access

    ### AWS Certificate Manager

    -   Single interface to manage both public and private certificates 
    -   Makes it easy to deploy certificates
    -   Protects and stores private certificates 
    -   Minimizes downtime and outages with automatic renewals

    ##### Protecting Data in Transit with Certificates

    -   TLS session is established between client and service endpoint
    -   X.509 certificates are used within a PKI
    -   Certificates verify the integrity of the server while preventing tampering and forgery

    ### AWS Secrets Manager

    -   Secure and scalable method for managing access to secrets
    -   Can meet regulatory and compliance requirements
    -   Rotates secrets safely without breaking applications
    -   Audits and monitors the lifecycle of secrets
    -   Can avoid putting secrets in code or config files

    ![AWS Secrets Manager Example](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/AWS%20Security/AWS-Secrets-Manager-Example.png)

    ##### Secrets Management Best Practices

    -   Store secrets safely and securely in a central repository
    -   Include an audit log for the use and misuse of secrets 
    -   Rotate secrets on a regular schedule
    -   Maintain access control of secrets

### Lab 3: Using AWS KMS to Encrypt Secrets Manager Secrets



## Data Security



## Infrastructure and Edge Protection



## Monitoring and Collecting Logs on AWS

##### Importance of Security Monitoring

Security monitoring involves the steps of identify, protect, detect, respond, and recover. Security controls are implemented to help protect and detect.

### Monitoring to identify threats

##### Examples of Indicators of Compromise

-   Significant or sudden increase in database reads
-   Abnormal HTML response sizes
-   Mismatched port-application traffic
-   Unusual DNS requests
-   Unusual outbound network traffic
-   Anomalies in privileged user activity
-   Geographical irregularity
-   Unusually high traffic at irregular hours
-   Multiple, repeated, or irregular login attempts 

##### Define a baseline

A baseline is a set of metrics used to define the normal working conditions of your system. 

-   Current state, configuration, and use of resources 
-   Peak network times and port and protocol use 
-   Identities, access, and authorizations based on requirement

##### AWS Solution: Amazon Detective

Detective ingests data from AWS CloudTrail logs, VPC Flow logs, GuardDuty findings, and EKS audit logs.

![AWS Detective Example](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/AWS%20Security/Detective-Example.png)

##### Another Solution: AWS Config

Continuously captures details on all config changes associated with your resources and also provides compliance monitoring and security analysis.

![AWS Config Example](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/AWS%20Security/Config-Example.png)

### Monitoring using logs

##### Benefits of logging

-   Provides continuous visibility of your resources and helps with every phase of IR strategy

##### Building a logging strategy

-   **Centralize storage**: Keep all log files in a secure, centralized repository with easy access for real-time log monitoring and analysis.
-   **Keep logs**: They can be used as part of a long-term analysis of application efficiency and also be necessary for auditing purposes.
-   **Log as much as you can**: If you can log it, you should do so.

##### VPC Flow Logs

-   Monitor remote logins
-   Examine traffic through trust zones with ACLs and security groups

![VPC Flow Log Example](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/AWS%20Security/VPC-Flow-Log-Example.png)

##### ELB Access Logs

-   Information about requests sent to Elastic Load Balancing is captured
-   Logs are then sent to S3 bucket and stored as compressed files
-   Original client IP address and port is reported in logs

##### S3 Server Access Logs

-   S3 server access logs track requests to your S3 bucket.
-   Each log record is an individual request.
-   It can also provide insights into customer base trends and patterns

## Responding to Threats

