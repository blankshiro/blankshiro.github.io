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

### IAM Threats

-   Compromised long-term credentials
-   Overly permissive and misconfigured policies
-   Anomalous IAM entity behaviour

### AWS Security Token Service

-   Best practice is to use short-term credentials
    -   To eliminate the need to rotate and revoke when they are no longer required
-   AWS STS as a web service that enables you to request temporary, limited-privilege credentials for users.
-   https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/image_previews/htb-lame.png?raw=true

![AWS STS Example](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/AWS Security/STS-Example.png)

## Account Management and Provisioning on AWS



## Managing Keys and Secrets on AWS