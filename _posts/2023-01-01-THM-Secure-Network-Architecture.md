---
layout: post
title: TryHackMe Secure Network Architecture
date: 2023-01-01
tags: [TryHackMe, Methodology]
---
>   Source: [Secure Network Architecture](https://tryhackme.com/room/introtosecurityarchitecture)

# I. Introduction

Networking is one of the most critical components of a corporate environment but can often be overlooked from a security standpoint. A properly designed network permits not only internet usage and device communication but also redundancy, optimization, and security.

In a well-designed network, if a switch goes down, then packets can be redistributed through another route with no loss in uptime. If a web server is compromised, it cannot traverse the network and access important information. A sysadmin should be confident that their servers are secure if a random device joins a network, knowing that the device is segmented from the rest of the network and cannot access those systems.

# II. Network Segmentation

Subnets are versatile for network organization, but they have limitations in security, especially with BYOD scenarios. When dealing with potentially compromised devices, VLANs (Virtual LANs) come into play. VLANs segment the network at layer two, isolating devices and enhancing security by using tags on network frames to specify their VLAN origin. The **802.1q** or **dot1q** tag will designate the VLAN that the traffic originated from.

![Diagram of a frame expanding the tag field of a header](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/922c8b652a916ec056dcc5ebc65fee00.png)

The **Native VLAN** is used for any traffic that is not tagged and passes through a switch. To configure a native VLAN, we must determine what interface and tag to assign them, then set the interface as the default native VLAN. 

VLANs, while useful for segmentation, can't directly access the internet or resources in other VLANs because they are isolated. Routers are used to enable communication between VLANs, In the past, this required physical connections, but now, a "Router on a Stick" (ROAS) design simplifies this. VLANs communicate with a router through a switch port designated as a trunk (**bridges**). VLANs are routed through the switch port, requiring only one trunk/connection between the switch and router, hence, "*on a stick*."

# III. Common Secure Network Architecture

**Security**, **optimization**, and **redundancy** should all be considered when designing a network, ideally without compromising one component.

**Security zones** can define **what** or **who** is in a VLAN and how traffic can travel **in** and **out**.

| **Zone **                | **Explanation **                                             | **Examples**                              |
| ------------------------ | ------------------------------------------------------------ | ----------------------------------------- |
| External                 | All devices and entities outside of our network or asset control. | Devices connecting to a web server        |
| DMZ (demilitarized zone) | Separates untrusted networks or devices from internal resources. | BYOD, remote users/guests, public servers |
| Trusted                  | Internal networks or devices. A device may be placed in the trusted zone if there is no confidential or sensitive information. | Workstations, B2B                         |
| Restricted               | Any high-risk servers or databases.                          | Domain controllers, client information    |
| Management               | Any devices or services dedicated to network or other device management. This zone is less commonly seen and can be grouped with the audit zone. | Virtualization management, backup servers |
| Audit                    | Any devices or services dedicated to security or monitoring. This zone is less commonly seen and can be grouped with management. | SIEM, telemetry                           |

While security zones mostly factor in what will happen internally, it is equally important to consider how new traffic or devices will enter the network, be assigned, and interact with internal systems. Most external traffic (HTTP, mail, etc.) will stay in the DMZ, but what if a remote user needs access to an internal resource? We can easily create rules for resources a user or device can access based on MAC, IP addresses, etc. We can then enforce these rules from network security controls.

![Diagram showing layers of a network with icons representing their components and firewalls in between each layer](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/99e8ced5bc8519608ef3d95b9528cf1a.png)

# IV. Network Security Policies and Controls

Policies aid in defining how network traffic is controlled. A network traffic policy may determine how and if a router will route traffic before other routing protocols are employed. **IEEE** has standardized a handful of access control and traffic policies, such as **QoS** (**Q**uality **o**f **S**ervice) (**802.11e**). There are still many other routing and traffic policies that are not standardized by IEEE but are commonly used by all vendors following the same objectives.

### Traffic Filtering

An ACL is used as a loose standard to create a ruleset for different implementations and access control protocols. ACLs within a router to decide whether to route or drop a packet based on the defined list.

An ACL contains **ACE(s)** (**A**ccess **C**ontrol **E**ntry) or rules that define a list’s profile based on pre-defined criteria (source address, destination address, etc.)

Formally, traffic filtering provides network security, validation, and segmentation by filtering network traffic based on pre-defined criteria.

# V. Zone-Pair Policies and Filtering

Network considerations often include size, traffic, and data correlation; when considering protocols and the requirements of a zone, we need to shift our focus toward traffic and correlation. Traffic correlation is standardized as the state of a packet, e.g. (protocol, process, direction, etc.)

### Firewalls

At the highest level, basic network firewalls are defined in two categories: **stateless** vs. **stateful**. 

A stateful firewall can better correlate information in a network connection. This allows the firewall to filter based on protocols, ports, processes, or other information from a device, etc.

One effective way of defining different actions based on the protocol and source/destination zone is using **zone-pairs**.

### Zone-Pairs

**Zone-pairs** are a direction-based and stateful policy that will enforce the traffic in single directions per each VLAN, hence, zone-pair. For example, **DMZ → LAN** or **LAN → DMZ.**

Each zone in a given topology must have a different zone-pair for each other in the topology and every possible direction. This approach provides the most visibility from a firewall and drastically improves the filtering capabilities.

# VI. Validating Network Traffic

### Scenario

An organization has proper zoning and routes in place. A zone-pair between the DMZ and LAN allows an HTTPS connection. Of course, the firewall should accept these connections.

In this scenario, let’s say a threat actor has landed an implant through phishing on a LAN machine. Assuming host defense mechanisms have failed, how can the implant be detected and monitored? If their beacon is using HTTPS through the DMZ. That will look like primarily legitimate traffic to your firewall and analysts.

To solve this issue, we must use SSL/TLS inspection to intercept HTTPS connections.

### SSL/TLS Inspection

SSL/TLS inspection involves using an SSL proxy to decrypt and analyze encrypted traffic, passing it to a Unified Threat Management (UTM) platform for deep inspection and processing. However, it raises concerns about potential security risks due to the use of a Man-in-the-Middle (MitM) approach. Organizations should carefully assess the pros and cons, considering the calculated risks involved. MitM essentially intercepts and decrypts encrypted traffic, which means that it can potentially expose sensitive data, including passwords and other confidential information, to the SSL proxy. This introduces a security risk, as any breach or vulnerability in the proxy could result in data exposure.

# VII. Addressing Common Attacks

### DHCP Snooping

**DHCP Snooping** is a security feature that operates at layer two and acts as a firewall between untrusted hosts and trusted DHCP servers. It validates and rate-limits DHCP traffic and maintains a DHCP Binding Database for storing leased IP addresses. It inspects conditions such as mismatched MAC and hardware addresses and relay agent addresses to determine if a DHCP packet should be dropped. Although not standardized by the IEEE, DHCP snooping generally remains consistent across vendors.

### Dynamic ARP Inspection

**Dynamic ARP Inspection** is a security feature that validates ARP packets in a network. It also validates and rate-limits ARP packets, intercepting, logging, and discarding packets if their MAC and IP addresses do not match. ARP inspection relies on the DHCP binding database created by DHCP snooping for its list of binding IP addresses.

To summarize, the DHCP binding database provides the expected MAC and IP address pair of untrusted hosts; ARP inspection will compare the source IP address and MAC address to the binding pair; if they are mismatched, it will drop the packet.
