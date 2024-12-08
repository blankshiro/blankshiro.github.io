---
layout: post
title: TryHackMe Principles of Security
date: 2023-01-01
tags: [TryHackMe, Methodology, CIA, Security Models]
---
>   Source: [TryHackMe Principles of Security](https://tryhackme.com/room/principlesofsecurity)

# I. CIA Triad

The CIA triad is a fundamental model for shaping security policies and assessing data's value within organizations. It underscores the interconnectedness of confidentiality, integrity, and availability in safeguarding information across various domains, including cybersecurity.

**Confidentiality**:

Confidentiality involves safeguarding data from unauthorized access and misuse. Organizations invariably store sensitive data, such as employee records and accounting documents. 

Ensuring confidentiality means protecting this data from individuals or entities not intended to access it. Access controls, vetting procedures, and strict access management play a pivotal role in upholding confidentiality. 

**Integrity**:

Integrity pertains to maintaining the accuracy and consistency of information, barring authorized changes. Information can be inadvertently altered due to careless access, system errors, or unauthorized intrusion. Integrity is preserved when information remains unaltered during storage, transmission, and usage that doesn't involve authorized modifications. 

Preventive measures like access control, stringent authentication, hash verifications, and digital signatures are employed to deter unauthorized alterations or breaches of confidentiality.

**Availability**:

Availability emphasizes that information must be accessible when authorized users require it. Downtime can tarnish an organization's reputation and result in financial losses. Ensuring availability involves multiple elements:

-   Reliable and well-tested hardware for information technology servers, often from reputable providers.
-   Implementation of redundant technology and services to mitigate primary system failures.
-   Implementation of robust security protocols to protect technology and services from potential attacks.

# II. Principles of Privileges

It is crucial to carefully manage and define the levels of access granted to individuals within an organization:

1.  **Role/Function**: The first factor is the individual's role or function within the organization. Different roles require varying degrees of access to IT systems.
2.  **Information Sensitivity**: The second factor considers the sensitivity of the information stored on the system. Highly sensitive data demands stricter access controls.

To effectively manage access rights, two key concepts come into play: **Privileged Identity Management (PIM)** and **Privileged Access Management (PAM)**:

-   **PIM** translates an individual's organizational role into an access role on the system. It deals with defining who has what level of access based on their role within the organization.
-   **PAM** goes beyond mere access assignment. It involves the active management of the privileges associated with an access role on a system. This encompasses a range of security measures, including password management, auditing policies, and efforts to reduce the system's vulnerability to attacks.

What is essential when discussing privilege and access controls is the principle of least privilege. Simply, users should be given the minimum amount of privileges, and only those that are absolutely necessary for them to perform their duties. Other people should be able to trust what people write to.

# III. Security Models

### Bell-La Padula Model

The Bell-La Padula Model is used to achieve confidentiality. This model has a few assumptions, such as an organisation's hierarchical structure it is used in, where everyone's responsibilities/roles are well-defined. It works by granting access to pieces of data (called objects) on a strictly need to know basis. This model uses the rule "no write down, no read up".

| **Advantages**                                               | **Disadvantages**                                            |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Policies in this model can be replicated to real-life organisations hierarchies (and vice versa). | Even though a user may not have access to an object, they will know about its existence - so it's not confidential in that aspect. |
| Simple to implement and understand, and has been proven to be successful. | The model relies on a large amount of trust within the organisation. |

![img](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/0e6e5d9d80785fc287b4a67e1453b295.png)

### Biba Model

The Biba model is used to achieve integrity. This model applies the rule to objects (data) and subjects (users) that can be summarised as "no write up, no read down". This rule means that subjects **can** create or write content to objects at or below their level but **can only** read the contents of objects above the subject's level.

| **Advantages**                                               | **Disadvantages**                                            |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| This model is simple to implement.                           | There will be many levels of access and objects. Things can be easily overlooked when applying security controls. |
| Resolves the limitations of the Bell-La Padula model by addressing both confidentiality and data integrity. | Often results in delays within a business. For example, a doctor would not be able to read the notes made by a nurse in a hospital with this model. |

![img](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/895ba351ef24ef6495d290222e49470e.png)
