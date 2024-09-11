---
layout: post
title: TryHackMe Threat Modelling
date: 2023-01-01
tags: [TryHackMe, Methodology, MITRE ATT&CK, DREAD, STRIDE, PASTA]
---
>   Source: [TryHackMe Threat Modelling](https://tryhackme.com/room/threatmodelling)

# I. What is Threat Modeling?

Threat modelling is a systematic approach to **identifying, prioritising, and addressing potential security threats** across the organisation. By simulating possible attack scenarios and assessing the existing vulnerabilities of the organisation's interconnected systems and applications, threat modelling enables organisations to develop proactive security measures and make informed decisions about resource allocation. 

# II. Modelling with MITRE ATT&CK

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a comprehensive, globally accessible knowledge base of cyber adversary behaviour and tactics.

Here are some use cases:

-   Identifying potential attack paths based on your infrastructure
    -   Based on your assets, the framework can map possible attack paths an attacker might use to compromise your organisation. For example, if your organisation uses Office 365, all techniques attributed to this platform are relevant to your threat modelling exercise.
-   Developing threat scenarios
    -   MITRE ATT&CK has attributed all tactics and techniques to known threat groups. This information can be leveraged to assess your organisation based on threat groups identified to be targeting the same industry.
-   Prioritising vulnerability remediation
    -   The information provided for each technique can be used to assess the significant impact that may occur if your organisation experiences a similar attack. Given this, your security team can identify the most critical vulnerabilities to address.

## ATT&CK Navigator

ATT&CK Navigator, is an open-source, web-based tool that helps visualise and navigate the complex landscape of the MITRE ATT&CK Framework. 

-   Creating a New Layer - Choose between Enterprise (networks), Mobile (smartphone & tablets), ICS (industrial control systems & CIIs)

-   Searching and Selecting Techniques

    -   Searching for keywords - press the magnifier button under the Selection Controls panel.  

        ![Search functionality example usage.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/04d12a47541923fc4a7b1ed229293fa1.png)

    -   Selecting Threat Groups - selecting a threat group in a search can highlight all techniques attributed to this threat group.

        ![Techniques highlighted after searching APT41.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/f11e5b772011876f8255d6abd97a1b1b.png)

-   Viewing, Sorting and Filtering Layers

    -   Filters - Allows you to filter techniques based on relevant platforms, such as OS or applications.

        ![Filtered list of techniques with O365 filter.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/4ecfb35e8b4b7784e55d46e0e419980f.png)

    -   Sorting - Allows you to sort the techniques by their alphabetical arrangement or numerical scores.

    -   Expand sub-techniques - View all underlying sub-techniques under each technique, expanding the view for all techniques.

        ![Expanding all sub-techniques in one view.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/57b9e0faedfe675aacbb7e039c2347bb.png)

### Example Scenario

You are tasked to utilise the MITRE ATT&CK framework for your threat modelling exercise. The organisation you're currently working with is in the financial services industry. Given that, some known threat groups targeting this industry are:

-   APT28 (Fancy Bear)
-   APT29 (Cozy Bear)
-   Carbanak
-   FIN7 (Carbanak/Fancy Bear)
-   Lazarus Group

In addition, your organisation uses the following technologies:

-   Google Cloud Platform (GCP) for cloud infrastructure
-   Online banking platform developed by internal developers
-   A Customer Relationship Management (CRM) platform

Lastly, the critical assets that you handle based on your business stakeholders are the following:

-   Customer financial data
-   Transaction records
-   Personally identifiable information (PII)

Given this scenario, you can use the MITRE ATT&CK framework and ATT&CK Navigator to map and understand the significant techniques attributed to the provided threat groups and those affecting GCP and web applications.

![View filtered with APT28 techniques.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/c0c43eff99b8a297d50ecc36170e0518.png)

![Techniques related to GCP.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/cb0e387e5b693a3d6eba7b839e5aef2d.png)

# III. Modelling with DREAD

The DREAD framework is a risk assessment model developed by Microsoft to evaluate and prioritise security threats and vulnerabilities. It is an acronym that stands for:

| **DREAD**           | **Definition**                                               |
| ------------------- | ------------------------------------------------------------ |
| **Damage**          | The potential harm that could result from the successful exploitation of a vulnerability. This includes data loss, system downtime, or reputational damage. |
| **Reproducibility** | The ease with which an attacker can successfully recreate the exploitation of a vulnerability. A higher reproducibility score suggests that the vulnerability is straightforward to abuse, posing a greater risk. |
| **Exploitability**  | The difficulty level involved in exploiting the vulnerability considering factors such as technical skills required, availability of tools or exploits, and the amount of time it would take to exploit the vulnerability successfully. |
| **Affected Users**  | The number or portion of users impacted once the vulnerability has been exploited. |
| **Discoverability** | The ease with which an attacker can find and identify the vulnerability considering whether it is publicly known or how difficult it is to discover based on the exposure of the assets (publicly reachable or in a regulated environment). |

-   **Damage** - How bad would an attack be?
-   **Reproducibility** - How easy is it to reproduce the attack?
-   **Exploitability** - How much work is it to launch the attack?
-   **Affected Users** - How many people will be impacted?
-   **Discoverability** - How easy is it to discover the vulnerability?

### Qualitative Analysis Using DREAD Framework

| DREAD Score     | 2.5                                                          | 5                                                     | 7.5                                                          | 10                                                           |
| --------------- | ------------------------------------------------------------ | ----------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Damage          | Minimal infrastructure information disclosure                | Minimal information disclosure related to client data | Limited PII leak                                             | Complete data leak                                           |
| Reproducibility | Multiple attack vectors requiring technical expertise        | Minor customisation for public exploits needed        | Little prerequisite technical skills needed to run the exploit | Users with public exploits can successfully reproduce the exploit |
| Exploitability  | Almost no public exploits are available and need customisation of scripts | Complicated exploit scripts available in the wild     | Minimal technical skills are required to execute public exploits | Reliable Metasploit module exists                            |
| Affected Users  | Almost none to a small subset                                | Around 10% of users                                   | More than half of the user base                              | All users                                                    |
| Discoverability | The significant effort needed to discover the vulnerability chains for the exploit to work | Requires a manual way of verifying the vulnerability  | Public scanning scripts not embedded in scanning tools exist | Almost all known scanning tools can find the vulnerability   |

Given this guideline, we can assess some known vulnerabilities in the application. Below is an example of scoring provided for each vulnerability.

1.  Unauthenticated Remote Code Execution (Score: 8)
    -   Damage (D): **10**
    -   Reproducibility (R): **7.5**
    -   Exploitability (E): **10**
    -   Affected Users (A): **10**
    -   Discoverability (D): **2.5**
2.  Insecure Direct Object References (IDOR) in User Profiles (Score: 6.5)
    -   Damage (D): **2.5**
    -   Reproducibility (R): **7.5** 
    -   Exploitability (E): **7.5**
    -   Affected Users (A): **10** 
    -   Discoverability (D): **5**
3.  Server Misconfiguration Leading to Information Disclosure (Score: 5)
    -   Damage (D): **0**
    -   Reproducibility (R): **10**
    -   Exploitability (E): **10**
    -   Affected Users (A): **0**
    -   Discoverability (D): **5**

# IV. Modelling with STRIDE

The STRIDE framework is a threat modelling methodology also developed by Microsoft, which helps identify and categorise potential security threats in software development and system design. The acronym STRIDE is based on six categories of threats, namely:

| **Category**               | **Definition**                                               | **Policy Violated** |
| -------------------------- | ------------------------------------------------------------ | ------------------- |
| **Spoofing**               | Unauthorised access or impersonation of a user or system.    | Authentication      |
| **Tampering**              | Unauthorised modification or manipulation of data or code.   | Integrity           |
| **Repudiation**            | Ability to deny having acted, typically due to insufficient auditing or logging. | Non-repudiation     |
| **Information Disclosure** | Unauthorised access to sensitive information, such as personal or financial data. | Confidentiality     |
| **Denial of Service**      | Disruption of the system's availability, preventing legitimate users from accessing it. | Availability        |
| **Elevation of Privilege** | Unauthorised elevation of access privileges, allowing threat actors to perform unintended actions. | Authorisation       |

### Checklist with STRIDE

| **Scenario**                                                 | **Spoofing** | **Tampering** | **Repudiation** | **Information Disclosure** | **Denial of Service** | **Elevation of Privilege** |
| ------------------------------------------------------------ | ------------ | ------------- | --------------- | -------------------------- | --------------------- | -------------------------- |
| **Sending a spoofed email, wherein the mail gateway lacks email security and logging configuration.** | ✔            |               | ✔               |                            |                       |                            |
| **Flooding a web server with many requests that lack load-balancing capabilities.** |              |               |                 |                            | ✔                     |                            |
| **Abusing an SQL injection vulnerability.**                  |              | ✔             |                 | ✔                          |                       |                            |
| **Accessing public cloud storage (such as AWS S3 bucket or Azure blob) that handles customer data**. |              |               |                 | ✔                          |                       |                            |
| **Exploiting a local privilege escalation vulnerability due to the lack of system updates and modifying system configuration for a persistent backdoor.** |              | ✔             |                 |                            |                       | ✔                          |

# V. Modelling with PASTA

Process for Attack Simulation and Threat Analysis, is a structured, risk-centric threat modelling framework designed to help organisations identify and evaluate security threats and vulnerabilities within their systems, applications, or infrastructure. PASTA provides a systematic, seven-step process that enables security teams to understand potential attack scenarios better, assess the likelihood and impact of threats, and prioritise remediation efforts accordingly.

### 7-Step Methodology

1.  Define the Objectives

    Establish the scope of the threat modelling exercise by identifying the systems, applications, or networks being analysed and the specific security objectives and compliance requirements to be met.

2.  Define the Technical Scope

    Create an inventory of assets, such as hardware, software, and data, and develop a clear understanding of the system's architecture, dependencies, and data flows.

3.  Decompose the Application

    Break down the system into its components, identifying entry points, trust boundaries, and potential attack surfaces. This step also includes mapping out data flows and understanding user roles and privileges within the system.

4.  Analyse the Threats 

    Identify potential threats to the system by considering various threat sources, such as external attackers, insider threats, and accidental exposures. This step often involves leveraging industry-standard threat classification frameworks or attack libraries.

5.  Vulnerabilities and Weaknesses Analysis

    Analyse the system for existing vulnerabilities, such as misconfigurations, software bugs, or unpatched systems, that an attacker could exploit to achieve their objectives. Vulnerability assessment tools and techniques, such as static and dynamic code analysis or penetration testing, can be employed during this step.

6.  Analyse the Attacks

    Simulate potential attack scenarios and evaluate the likelihood and impact of each threat. This step helps determine the risk level associated with each identified threat, allowing security teams to prioritise the most significant risks.

7.  Risk and Impact Analysis

    Develop and implement appropriate security controls and countermeasures to address the identified risks, such as updating software, applying patches, or implementing access controls. The chosen countermeasures should be aligned with the organisation's risk tolerance and security objectives.

