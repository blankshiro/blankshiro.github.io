---
layout: post
title: TryHackMe Networking
date: 2023-01-01
tags: [TryHackMe, Methodology, OSI Model]
---
>   Source: [TryHackMe Networking](https://tryhackme.com/room/introtonetworking)

# I. OSI Model

In the realm of computer networking, the OSI (Open Systems Interconnection) Model is a foundational framework comprising seven distinct layers. Each layer plays a crucial role in facilitating the seamless flow of data (from higher level to lower level) across networks. 

"**All People Seem to Need Data Processing**".

1.  **Layer 7 - Application:**
    -   Acts as the interface between network applications and the network itself.
    -   Facilitates data transmission for user programs.
2.  **Layer 6 - Presentation:**
    -   Translates (present) data from the application layer into a standardized format.
    -   Manages encryption, compression, and other data transformations.
3.  **Layer 5 - Session:**
    -   Establishes and maintains communication sessions between devices.
    -   Ensures synchronization with the remote session layer.
4.  **Layer 4 - Transport:**
    -   Chooses the transmission protocol, such as TCP (reliable) or UDP (fast).
    -   Segments data for efficient transmission.
5.  **Layer 3 - Network:**
    -   Determines the best route for data transmission using logical addressing (e.g., IP addresses).
    -   Organizes networks and routes data accordingly.
6.  **Layer 2 - Data Link:**
    -   Focuses on physical addressing, adding MAC (Media Access Control) addresses.
    -   Verifies data integrity (no corruption) during transmission and ensures compatibility for transmission.
    -   Data is formatted in preparation for transmission.
7.  **Layer 1 - Physical:**
    -   Handles the physical hardware, transmitting and receiving data.
    -   Converts binary data into signals for network transmission and vice versa.

# II. Encapsulation

As data moves down each layer of the OSI model, specific layer-related information is added to the start of the transmission. This whole process is referred to as *encapsulation;* the process by which data can be sent from one computer to another.

![Encapsulation process](https://muirlandoracle.co.uk/wp-content/uploads/2020/02/image.jpeg)

-   Layers 7, 6, and 5 refer to the encapsulated data simply as "data."
-   At the Transport Layer, it becomes a "segment" or a "datagram," depending on the selected protocol (TCP or UDP).
-   The Network Layer designates it as a "packet."
-   The Data Link Layer transforms it into a "frame."
-   When transmitted across a network, the frame is broken down into individual "bits."

Upon reaching the receiving computer, the data goes through the reverse process, starting at the Physical Layer and moving upward to the Application Layer. At each step, the added information is stripped off. This reversal process is referred to as de-encapsulation. 



