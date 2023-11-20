---
layout: post
title: LTE Vulnerabilities Research
date: 2023-10-01
categories: [Research, LTE]
tags: [Research, LTE]
---
>   Source: [NSE](https://nse.digital/pages/guides/Wireless/lte-hacking.html)

# I. What is LTE?
LTE, or Long-Term Evolution, is a mobile telecommunication standard that represents the 4G generation of wireless technology. While it's commonly referred to as 4G LTE, it's essential to note that the original LTE doesn't fully meet the technical criteria of 4G and is sometimes called 3.95G. LTE Advanced is a significant improvement that aligns with the 4G standards and is widely used by carriers worldwide. It's crucial to recognize that LTE is an implementation of 4G standards.

# II. LTE Architecture
The LTE network consists of three main components:
- User Equipment (UE): Any devices with SIM cards which has a universal subscriber identity module (USIM) application.
- eNodeB (evolved NodeB): Base stations that connect UEs to the network.
    - E-UTRAN is a geographical area which consists of several eNodeBs (base stations) which can provide LTE network services to UE within the cell. 
- EPC (Evolved Packet Core): The core network responsible for providing UEs with network service.

![LTE Architecture](https://nse.digital/pages/guides/images/lte-architecture.png)

##### Attach procedure in LTE
1. When UE initiates the attach procedure, it first scans the surrounding spectrum to acknowledge eNodeBs with the highest power and then it will perform the random access procedure.
    - Such random access procedure is necessary since UE needs to synchronize its clock with the network and also be assigned a dedicated channel to receive messages.
2. It will then set up the RRC connection with the eNodeB.
3. After RRC connection establishment, UE will send an attach request message containing its temporary identity to MME, which will later retrieve the materials for the authentication.
4. Then these material will be contained in the authentication request message that will be sent to UE.
5. After receiving the message, UE will send back an authentication response message to authenticate the network.
6. If authentication is successful, then the UE will enter the security complete mode.
7. With the message attachaccept arriving, the attach procedure is complete.
> During initial attach, IMSI is transmitted through LTE air interface within plaintext messages. This gives an adversary a chance to receive these messages and IMSI inside.

# III. LTE Security
LTE incorporates robust security measures to ensure the confidentiality, integrity, and authenticity of mobile communication. Key elements include a hardware-protected 128-bit key (K) stored in the SIM card and the carrier's network. The International Mobile Subscriber Identity (IMSI) number plays a crucial role in user authentication.

# IV. Types of Attacks
## IMSI Catchers
IMSI catchers exploit unencrypted packets exchanged between UEs and eNodeBs during initial communication. These devices can identify and track mobile devices based on their unique IMSI numbers.
  
To perform an IMSI Catcher attack, you create a fake cell tower that mimics a real one. By getting your target device to connect to it (since devices connect to the strongest signal), you force the device to reveal its IMSI number.

## Denial Of Service
### Jamming in LTE DoS Attacks
One method for LTE DoS attacks is jamming. Attackers use hardware to disrupt wireless communication by transmitting signals on the same frequency.

### Fake Base Station DoS
Another approach to DoS attacks involves creating a fake base station that victims connect to. This gives the attacker control over the entry point into the network, enabling them to halt all communication or target specific services or types of communication.

## DNS Spoofing
While user data in LTE is encrypted, the lack of integrity protection in the data link layer leaves room for rogue base stations to modify messages, potentially redirecting users to malicious servers.

## Eavesdropping Attacks
LTE's strong encryption makes it difficult to intercept user data directly. While direct eavesdropping on LTE data is unlikely, there are still potential attack scenarios. In situations like DNS spoofing and IMSI Catchers, a MiTM attack between the base station and the UE can enable attackers to perform various malicious activities. Another tactic is a downgrade attack, where attackers force a UE to switch to an older and less secure mobile communication standard such as GSM, to potentially snoop on the traffic. These attacks typically involve creating a fake base station to lure the victim's device.

# V. Setting Up Our Own Environment
LTE Software Defined Radios (SDRs) enable individuals to recreate LTE components using software and basic wireless hardware. [srsRAN_4G](https://github.com/srsran/srsRAN_4G) is an open-source solution that allows users to emulate LTE base stations for experimentation.
